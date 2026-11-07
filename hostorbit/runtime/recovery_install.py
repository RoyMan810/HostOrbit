"""Install previously Owner-authorized recovery data into fresh native namespaces.

The source is a Root-private consumed Rescue ledger, never an arbitrary tar,
runtime configuration or Web input. Source ACL consumers are preserved exactly;
all automation remains blocked until a separate future activation protocol.
"""

import argparse
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from nacl.exceptions import CryptoError
from nacl.secret import Aead
from nacl.signing import SigningKey

from ..admission import Admission
from ..database import Store
from ..errors import Denied
from ..migrations import _verify as verify_app, schema_rows
from .archive_stream import parse_manifest
from .authority import Authority, host_binding
from .broker import Broker
from .controller_backup import verify_provenance_claims
from .coordinator import Coordinator
from .credentials import seal_credential
from .pins import _copy_database, _metadata
from .policy import Policy
from .protocol import SHA256, canonical, checksum, fields, text
from .recovery_import import _trusted_path
from .rescue import ENV, harden, validate_request, wipe
from .storage import Journal, new_private_file, process_lock, protected_bytes


def _read(path, maximum=65536):
    return protected_bytes(path, owner=0, maximum=maximum, exact_mode=0o600)


def _require_root():
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")


def _record(state):
    state = _trusted_path(state)
    with Journal(state / "recovery.sqlite3").connect() as db:
        row = db.execute("SELECT * FROM request WHERE id=1").fetchone()
    if row is None or row["state"] != "IMPORTED" or (state / "identity.cred").exists():
        raise Denied("RECOVERY_IMPORT_NOT_COMPLETE")
    if os.path.lexists(state / "installation.claim.json"):
        raise Denied("RECOVERY_INSTALLATION_CONSUMED")
    request = parse_manifest(row["value"])
    validate_request(request, now=request["issued_at"])  # Transport has already been consumed; no new age gate.
    text(row["bundle_sha256"], SHA256)
    destination = _trusted_path(row["destination"])
    receipt = fields(parse_manifest(_read(destination / "recovery.json")), ("v", "type", "status", "target_id", "source_instance",
        "source_backup_hash", "bundle_sha256", "quarantined_targets", "services_installed", "activation", "restore_verified", "backup_gate"))
    if (type(receipt["v"]) is not int or receipt["v"] != 1 or receipt["type"] != "hostorbit.recovery-import"
            or receipt["status"] != "READ_ONLY_RECOVERY" or receipt["target_id"] != request["target_id"]
            or receipt["bundle_sha256"] != row["bundle_sha256"] or receipt["services_installed"] is not False
            or receipt["activation"] != "MANUAL_FENCING_REQUIRED" or receipt["backup_gate"] != "DENIED"
            or receipt["restore_verified"] is not False):
        raise Denied("RECOVERY_RECEIPT_INVALID")
    for path in (destination / name for name in ("app", "source", "vault", "vault/objects", "credentials", "control-gate")):
        _trusted_path(path)
    if Admission(destination / "writer-admission").state()["phase"] != "READ_ONLY_RECOVERY":
        raise Denied("RECOVERY_PROFILE_REQUIRED")
    policy = Policy.load(destination / "source/targets.json")
    if receipt["quarantined_targets"] != sorted(policy.targets):
        raise Denied("RECOVERY_RECEIPT_INVALID")
    envelope = parse_manifest(_read(destination / "source/provenance.json"))
    anchor = _read(destination / "source/gate.pub", 32)
    claims = verify_provenance_claims(envelope, anchor)
    if (checksum(envelope) != request["source_envelope_sha256"] or claims["ciphertext_sha256"] != receipt["source_backup_hash"]
            or claims["manifest"]["source_instance"] != receipt["source_instance"]):
        raise Denied("RECOVERY_SOURCE_CHANGED")
    if hashlib.sha256(_read(destination / "source/pin.json", 32 * 1024**2)).hexdigest() != claims["manifest"]["pin_sha256"]:
        raise Denied("RECOVERY_SOURCE_CHANGED")
    policy_record = next(item for item in claims["manifest"]["files"] if item["path"] == "targets.json")
    if hashlib.sha256(_read(destination / "source/targets.json")).hexdigest() != policy_record["sha256"]:
        raise Denied("RECOVERY_POLICY_CHANGED")
    with Journal(destination / "control-gate/gate.sqlite3").connect() as db:
        gate = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
        if (gate is None or gate["activated"] != 0 or gate["state"] != "RECOVERY_HOLD"
                or gate["instance_id"] != request["target_id"] or gate["host_binding"] != host_binding()
                or gate["policy_digest"] != policy.digest or gate["epoch"] <= claims["manifest"]["gate_epoch"]
                or db.execute("SELECT 1 FROM attempts").fetchone()):
            raise Denied("RECOVERY_AUTHORITY_INVALID")
    key = SigningKey(_read(destination / "control-gate/signing.key", 32))
    if bytes(key.verify_key) != _read(destination / "gate.pub", 32) or bytes(key.verify_key) == anchor:
        raise Denied("RECOVERY_AUTHORITY_INVALID")
    store = Store(destination / "app/controller.sqlite3")
    with store.connect(readonly=True) as db:
        db.execute("BEGIN")
        verify_app(db, claims["manifest"]["schema"])
        owner = db.execute("SELECT id FROM users WHERE role='Owner' AND disabled=0").fetchall()
        event = db.execute("SELECT * FROM audit WHERE event='recovery.imported' AND correlation_id=?", (request["target_id"],)).fetchone()
        source = db.execute("SELECT digest FROM audit WHERE seq=?", (claims["manifest"]["audit_sequence"],)).fetchone()
        if (len(owner) != 1 or owner[0][0] != row["owner_id"] or event is None
                or json.loads(event["details"]).get("bundle_sha256") != row["bundle_sha256"]
                or (source[0] if source else "0" * 64) != claims["manifest"]["audit_head"]):
            raise Denied("RECOVERY_APPLICATION_INVALID")
        if claims["manifest"]["schema"] == 2 and (db.execute("SELECT 1 FROM resources WHERE enabled<>0").fetchone()
                or db.execute("SELECT 1 FROM jobs WHERE status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')").fetchone()):
            raise Denied("RECOVERY_AUTOMATION_NOT_QUARANTINED")
    return state, destination, request, row, receipt, claims, policy


@contextmanager
def _key(destination):
    wrapped = _read(destination / "credentials/broker-dek.cred", 16384)
    result = subprocess.run(["/usr/bin/systemd-creds", "decrypt", "--name=broker-dek", "-", "-"], input=wrapped,
                            capture_output=True, timeout=15, env=ENV)
    if result.returncode or len(result.stdout) != 32:
        raise Denied("RECOVERY_HOST_CREDENTIAL_UNAVAILABLE")
    key = bytearray(result.stdout)
    try:
        pin = parse_manifest(_read(destination / "source/pin.json", 32 * 1024**2))
        if (pin["key_generations"] != [1] or pin["key_fingerprints"] != {"1": hashlib.sha256(key).hexdigest()}):
            raise Denied("RECOVERY_KEYSET_INVALID")
        aead, references = Aead(bytes(key)), []
        with Journal(destination / "vault/vault.sqlite3").connect() as db:
            from .vault import _SCHEMA as vault_schema
            with closing(sqlite3.connect(":memory:")) as expected:
                expected.executescript(vault_schema)
                if schema_rows(db) != schema_rows(expected):
                    raise Denied("RECOVERY_VAULT_INVALID")
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
                raise Denied("RECOVERY_VAULT_INVALID")
            for row in db.execute("SELECT * FROM secrets ORDER BY ref"):
                metadata = _metadata(row)
                digest = text(row["object_digest"], SHA256)
                encrypted = _read(destination / "vault/objects" / digest, 9000)
                if hashlib.sha256(encrypted).hexdigest() != digest:
                    raise Denied("RECOVERY_VAULT_INVALID")
                try:
                    secret = aead.decrypt(encrypted, canonical(metadata))
                except CryptoError:
                    raise Denied("RECOVERY_VAULT_INVALID") from None
                del secret
                references.append({"ref": row["ref"], "state": row["state"], "object_digest": digest,
                                   "metadata_sha256": checksum(metadata), "key_generation": 1})
        if references != pin["references"]:
            raise Denied("RECOVERY_VAULT_INVALID")
        yield bytes(key), pin
    finally:
        wipe(key)


def check(state):
    _require_root()
    harden()
    state, source, request, row, receipt, claims, policy = _record(state)
    with _key(source):
        pass
    return {"status": "RECOVERY_INSTALLATION_ELIGIBLE", "target_id": request["target_id"], "schema": claims["manifest"]["schema"],
            "bundle_sha256": row["bundle_sha256"], "target_policy": {"v": 1, "targets": [policy.targets[k].value for k in sorted(policy.targets)]},
            "mode": "READ_ONLY_RECOVERY", "backup_gate": "DENIED"}


def apply(state, config, artifact_digest):
    _require_root()
    harden()
    text(artifact_digest, SHA256)
    state = _trusted_path(state)
    with process_lock(state / "installation.lock"):
        state, source, request, row, receipt, claims, policy = _record(state)
        if Policy.load(config["targets"]).digest != policy.digest:
            raise Denied("RECOVERY_POLICY_CHANGED")
        # The signed installer supplies only its fixed new namespaces.
        expected = {"database": "/var/lib/hostorbit/app/controller.sqlite3", "supervisor_directory": "/var/lib/hostorbit/control-gate",
                    "broker_directory": "/var/lib/hostorbit/broker", "vault_directory": "/var/lib/hostorbit/vault",
                    "writer_directory": "/var/lib/hostorbit/writer-admission", "vault_credential": "/etc/hostorbit/credentials/broker-dek.cred",
                    "public_verify_key": "/etc/hostorbit/gate.pub"}
        if any(config[k] != value for k, value in expected.items()):
            raise Denied("RECOVERY_INSTALLATION_LAYOUT_INVALID")
        if any(Path(config["database"]).parent.iterdir()):
            raise Denied("RECOVERY_INSTALLATION_NOT_EMPTY")
        for name in ("supervisor_directory", "broker_directory", "vault_directory"):
            if any(Path(config[name]).iterdir()):
                raise Denied("RECOVERY_INSTALLATION_NOT_EMPTY")
        if os.path.lexists(config["writer_directory"]) or os.path.lexists(config["vault_credential"]) or os.path.lexists(config["public_verify_key"]):
            raise Denied("RECOVERY_INSTALLATION_NOT_EMPTY")
        with _key(source) as (key, pin):
            claim = {"v": 1, "type": "hostorbit.recovery-installation", "target_id": request["target_id"],
                     "bundle_sha256": row["bundle_sha256"], "artifact_sha256": artifact_digest, "mode": "READ_ONLY_RECOVERY"}
            new_private_file(state / "installation.claim.json", canonical(claim))
            # Root creates the private journals before final Broker ownership.
            for name in ("broker_directory", "vault_directory"):
                os.chown(config[name], 0, 0)
            writers = Admission.initialize(config["writer_directory"])
            writers.publish("READ_ONLY_RECOVERY")
            authority = Authority.initialize(config["supervisor_directory"], policy)
            try:
                with authority.journal.write() as db:
                    db.execute("UPDATE gate SET activated=0,state='RECOVERY_HOLD',instance_id=?,epoch=? WHERE id=1",
                               (request["target_id"], claims["manifest"]["gate_epoch"] + 2))
                Coordinator.initialize(Path(config["supervisor_directory"]) / "snapshots", writers)
                new_private_file(config["public_verify_key"], bytes(authority.key.verify_key))
                Path(config["public_verify_key"]).chmod(0o644)
            finally:
                authority.close()
            Broker.initialize(config["broker_directory"], policy)
            source_store = Store(source / "app/controller.sqlite3")
            source_store.version = claims["manifest"]["schema"]
            _copy_database(source_store, Path(config["database"]), lambda: None)
            with closing(sqlite3.connect(config["database"], autocommit=True)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                for table in ("reauth", "sessions", "bootstrap"):
                    db.execute(f"DELETE FROM {table}")
                if claims["manifest"]["schema"] == 2:
                    db.execute("UPDATE jobs SET permit=NULL,claimed_by=NULL,claim_nonce=NULL")
                Store.event(db, at=time.time_ns() // 10**9, actor=row["owner_id"], kind="recovery.installed",
                            target=request["target_id"], outcome="READ_ONLY_RECOVERY", correlation=request["target_id"], details=claim)
                db.execute("COMMIT")
            for path in Path(config["database"]).parent.iterdir():
                os.chown(path, config["app_uid"], config["app_gid"])
                path.chmod(0o660)
            vault = Path(config["vault_directory"])
            (vault / "objects").mkdir(mode=0o700)
            _copy_database(Journal(source / "vault/vault.sqlite3"), vault / "vault.sqlite3", lambda: None)
            with closing(sqlite3.connect(vault / "vault.sqlite3", autocommit=True)) as db:
                db.execute("PRAGMA journal_mode=WAL")
            for item in pin["files"]:
                if item["path"].startswith("objects/"):
                    new_private_file(vault / item["path"], _read(source / "vault" / item["path"], 9000))
            seal_credential(key, config["vault_credential"])
            for directory in (Path(config["broker_directory"]), vault):
                for path in (*directory.rglob("*"), directory):
                    os.chown(path, config["broker_uid"], config["broker_gid"])
                    path.chmod(0o700 if path.is_dir() else 0o600)
            new_private_file(Path(config["supervisor_directory"]) / "recovery-installation.json", canonical(claim))
            new_private_file(state / "installation.data-ready.json", canonical(claim))
            return {**claim, "status": "READ_ONLY_RECOVERY", "activation": "MANUAL_FENCING_REQUIRED", "restore_verified": False}


def finish(state, artifact_digest):
    """Called by the signed installer only after service/HTTP smoke checks."""
    _require_root()
    harden()
    state = _trusted_path(state)
    text(artifact_digest, SHA256)
    claim = parse_manifest(_read(state / "installation.claim.json"))
    if (_read(state / "installation.data-ready.json") != canonical(claim)
            or claim["artifact_sha256"] != artifact_digest or claim["mode"] != "READ_ONLY_RECOVERY"):
        raise Denied("RECOVERY_INSTALLATION_BINDING_INVALID")
    metadata = parse_manifest(_read(Path("/opt/hostorbit/installation.json")))
    if metadata["manifest_sha256"] != artifact_digest or metadata["recovery"] != "READ_ONLY_RECOVERY":
        raise Denied("RECOVERY_INSTALLATION_BINDING_INVALID")
    from .cli import configuration
    config = configuration(Path("/etc/hostorbit/runtime.json"))
    if Admission(config["writer_directory"]).state()["phase"] != "READ_ONLY_RECOVERY":
        raise Denied("RECOVERY_PROFILE_REQUIRED")
    with Journal(Path(config["supervisor_directory"]) / "gate.sqlite3").connect() as db:
        gate = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
        if gate["activated"] != 0 or gate["instance_id"] != claim["target_id"]:
            raise Denied("RECOVERY_AUTHORITY_INVALID")
    new_private_file(state / "installation.complete.json", canonical(claim))
    return {"status": "READ_ONLY_RECOVERY", "target_id": claim["target_id"], "services_installed": True,
            "activation": "MANUAL_FENCING_REQUIRED", "restore_verified": False, "backup_gate": "DENIED"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "apply", "finish"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--artifact-sha256")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            result = check(args.state)
        elif args.command == "finish":
            result = finish(args.state, args.artifact_sha256)
        else:
            from .cli import configuration
            result = apply(args.state, configuration(args.config), args.artifact_sha256)
        print(canonical(result).decode())
        return 0
    except Exception as error:
        print(error.code if isinstance(error, Denied) else "RECOVERY_INSTALLATION_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
