"""Root console admission and quarantined data import onto a new empty target.

This prepares native data, not an executable installation. Source deployment
configuration is evidence only. No services, automation or old permits start.
"""

import base64
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import subprocess
import time

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError

from ..admission import Admission
from ..database import Store, identifier
from ..errors import Denied
from ..queue import JobQueue
from .archive_stream import AGE_KEYGEN_PATH, AGE_PATH, parse_manifest, trusted_keygen
from .authority import Authority
from .broker import Broker
from .controller_backup import verify_provenance_claims
from .coordinator import Coordinator
from .credentials import seal_credential
from .policy import Policy
from .protocol import SHA256, canonical, checksum, fields, text
from .rescue import ENV, ciphertext_stream, decrypt, harden, validate_request, wipe
from .rescue_payload import database, unpack, verify
from .storage import Journal, directory_sync, new_private_file, process_lock, protected_bytes


_SCHEMA = """
CREATE TABLE request(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL,
 destination TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('REQUESTED','IMPORTING','IMPORTED','FAILED')),
 boot_id TEXT NOT NULL, deadline_ns INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 bundle_sha256 TEXT, owner_id TEXT);
"""


def _boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _trusted_path(path, *, owner=0):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise Denied("RECOVERY_DIRECTORY_UNTRUSTED")
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise Denied("RECOVERY_DIRECTORY_NOT_PRIVATE")
    return path


def _identity_credential(data=None, *, ciphertext=None):
    args = (["encrypt", "--with-key=host"] if data is not None else ["decrypt"])
    result = subprocess.run(["/usr/bin/systemd-creds", *args, "--name=rescue-identity", "-", "-"],
                            input=data if data is not None else ciphertext, capture_output=True, timeout=15, env=ENV)
    if result.returncode or not 60 <= len(result.stdout) <= 16384:
        raise Denied("RECOVERY_IDENTITY_SEAL_FAILED")
    return result.stdout


class RecoveryTarget:
    def __init__(self, directory, *, owner=0, age_path=AGE_PATH):
        if os.geteuid() != owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        self.owner, self.directory, self.age_path = owner, _trusted_path(directory, owner=owner), age_path
        self.journal = Journal(self.directory / "recovery.sqlite3")

    @classmethod
    def issue(cls, directory, destination, source_envelope_sha256, *, keygen_path=AGE_KEYGEN_PATH, owner=0, age_path=AGE_PATH):
        if os.geteuid() != owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        harden()
        text(source_envelope_sha256, SHA256)
        directory, destination = Path(directory).absolute(), Path(destination).absolute()
        # Both are newly reserved private namespaces. Existing empty directories
        # are also refused: the tool never takes ownership of someone else's path.
        for path in (directory, destination):
            _trusted_path(path.parent, owner=owner)
            if os.path.lexists(path):
                raise Denied("RECOVERY_TARGET_NOT_NEW")
        if directory == destination or directory in destination.parents or destination in directory.parents:
            raise Denied("RECOVERY_LAYOUT_INVALID")
        executable = trusted_keygen(keygen_path, owner=owner)
        identity = bytearray(subprocess.run([executable], check=True, capture_output=True, timeout=5, env=ENV).stdout)
        try:
            public = subprocess.run([executable, "-y"], input=identity, check=True, capture_output=True, timeout=5, env=ENV).stdout.decode().strip()
            now = int(time.time())
            request = validate_request({"v": 1, "type": "hostorbit.recovery-request", "target_id": identifier(),
                "recipient": public, "recipient_fingerprint": hashlib.sha256(public.encode("ascii")).hexdigest(),
                "challenge": secrets.token_hex(32), "issued_at": now, "expires_at": now + 900,
                "source_envelope_sha256": source_envelope_sha256})
            wrapped = _identity_credential(identity)
            for path in (directory, destination):
                path.mkdir(mode=0o700)
                directory_sync(path.parent)
            journal = Journal.initialize(directory / "recovery.sqlite3", _SCHEMA)
            new_private_file(directory / "identity.cred", wrapped)
            with journal.write() as db:
                db.execute("INSERT INTO request(id,value,destination,state,boot_id,deadline_ns) VALUES(1,?,?,'REQUESTED',?,?)",
                           (canonical(request), str(destination), _boot(), time.monotonic_ns() + 900 * 10**9))
            new_private_file(directory / "request.json", canonical(request))
            return request
        finally:
            wipe(identity)

    def _request(self):
        with self.journal.connect() as db:
            row = db.execute("SELECT * FROM request WHERE id=1").fetchone()
        if row is None or row["state"] != "REQUESTED":
            raise Denied("RECOVERY_REQUEST_CONSUMED")
        if row["boot_id"] != _boot() or time.monotonic_ns() >= row["deadline_ns"]:
            raise Denied("RESCUE_REQUEST_EXPIRED")
        if row["attempts"] >= 5:
            raise Denied("RECOVERY_AUTH_LOCKED")
        request = validate_request(parse_manifest(row["value"]))
        destination = _trusted_path(row["destination"], owner=self.owner)
        if any(destination.iterdir()):
            raise Denied("RECOVERY_TARGET_NOT_EMPTY")
        return row, request, destination

    def accept(self, bundle, *, owner_digest, username, password):
        harden()
        text(owner_digest, SHA256, "OWNER_DIGEST_REQUIRED")
        plaintext = identity = None
        with process_lock(self.directory / "import.lock"):
            row, request, destination = self._request()
            try:
                with ciphertext_stream(bundle) as source:
                    digest = hashlib.file_digest(source, "sha256").hexdigest()
                    if not hmac.compare_digest(digest, owner_digest):
                        raise Denied("OWNER_DIGEST_MISMATCH")
                    source.seek(0)
                    wrapped = protected_bytes(self.directory / "identity.cred", owner=self.owner, exact_mode=0o600)
                    identity = bytearray(_identity_credential(ciphertext=wrapped))
                    plaintext = decrypt(source, identity, age_path=self.age_path, tool_owner=self.owner)
                    source.seek(0)
                    if not hmac.compare_digest(hashlib.file_digest(source, "sha256").hexdigest(), owner_digest):
                        raise Denied("OWNER_DIGEST_MISMATCH")
                members = unpack(plaintext)
                header = fields(parse_manifest(bytes(members.pop("recovery.json", b""))),
                                ("v", "type", "request", "source_envelope", "trusted_source_key", "summary"))
                if (type(header["v"]) is not int or header["v"] != 1 or header["type"] != "hostorbit.recovery-bundle"
                        or header["request"] != request or checksum(header["source_envelope"]) != request["source_envelope_sha256"]):
                    raise Denied("RECOVERY_BINDING_INVALID")
                anchor = bytes.fromhex(text(header["trusted_source_key"], SHA256))
                claims = verify_provenance_claims(header["source_envelope"], anchor)
                summary = verify(members, claims, anchor)
                if summary != header["summary"]:
                    raise Denied("RECOVERY_BINDING_INVALID")
                try:
                    owner_id = authenticate_owner(members, claims["manifest"]["schema"], username, password)
                except Denied:
                    with self.journal.write() as db:
                        db.execute("UPDATE request SET attempts=attempts+1 WHERE id=1")
                    raise
                self._request()  # Recheck expiry, emptiness and boot after crypto/auth.
                import shutil
                if shutil.disk_usage(destination).free < len(plaintext) * 2 + 64 * 1024**2:
                    raise Denied("RECOVERY_SPACE_INSUFFICIENT")
                # Durable one-time consumption precedes the first data write.
                # Kill/ENOSPC here leaves IMPORTING/FAILED, never a reusable key.
                with self.journal.write() as db:
                    if db.execute("UPDATE request SET state='IMPORTING',bundle_sha256=?,owner_id=? WHERE id=1 AND state='REQUESTED'",
                                  (owner_digest, owner_id)).rowcount != 1:
                        raise Denied("RECOVERY_REQUEST_CONSUMED")
                try:
                    result = import_data(destination, members, claims, request, owner_id, owner_digest,
                                         source_envelope=header["source_envelope"], owner=self.owner)
                    with self.journal.write() as db:
                        db.execute("UPDATE request SET state='IMPORTED' WHERE id=1")
                    (self.directory / "identity.cred").unlink()
                    directory_sync(self.directory)
                    return result
                except BaseException:
                    with self.journal.write() as db:
                        db.execute("UPDATE request SET state='FAILED' WHERE id=1")
                    raise
            finally:
                if plaintext is not None:
                    wipe(plaintext)
                if identity is not None:
                    wipe(identity)


def authenticate_owner(members, schema, username, password):
    with database(members["controller/app.sqlite3"], schema) as db:
        row = db.execute("SELECT id,password_hash FROM users WHERE username=? AND role='Owner' AND disabled=0", (username,)).fetchone()
    try:
        if row is None or not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ValueError()
        parameters = extract_parameters(row["password_hash"])
        if (parameters.type != Type.ID or parameters.version != 19 or parameters.time_cost != 3
                or parameters.memory_cost != 65536 or parameters.parallelism != 4
                or parameters.hash_len != 32 or parameters.salt_len != 16):
            raise ValueError()
        PasswordHasher().verify(row["password_hash"], password)
        return row["id"]
    except (ValueError, InvalidHashError, VerificationError):
        raise Denied("RECOVERY_OWNER_AUTH_REQUIRED") from None


def import_data(destination, members, claims, request, owner_id, bundle_sha256, *, source_envelope, owner=0):
    """Only the trusted console calls this after exact digest + Owner auth.

    Layout remains private and service-inert pending installation integration.
    No source runtime config, old signer, permits or receipts become authority.
    """
    destination = _trusted_path(destination, owner=owner)
    if any(destination.iterdir()):
        raise Denied("RECOVERY_TARGET_NOT_EMPTY")
    for name in ("app", "vault", "vault/objects", "credentials", "source"):
        (destination / name).mkdir(mode=0o700)
    policy = Policy(parse_manifest(bytes(members["controller/targets.json"]))["targets"])
    admission = Admission.initialize(destination / "writer-admission", owner=owner)
    admission.publish("READ_ONLY_RECOVERY")
    gate = Authority.initialize(destination / "control-gate", policy)
    try:
        with gate.journal.write() as db:
            db.execute("UPDATE gate SET activated=0,state='RECOVERY_HOLD',instance_id=?,epoch=? WHERE id=1",
                       (request["target_id"], claims["manifest"]["gate_epoch"] + 1))
        Coordinator.initialize(destination / "control-gate/snapshots", admission)
        new_private_file(destination / "gate.pub", bytes(gate.key.verify_key))
    finally:
        gate.close()
    Broker.initialize(destination / "broker", policy)
    for name, raw in members.items():
        if name.startswith("controller/"):
            leaf = name.removeprefix("controller/")
            path = destination / "app/controller.sqlite3" if leaf == "app.sqlite3" else destination / "source" / leaf
            new_private_file(path, raw)
        elif name.startswith("vault/") and name not in {"vault/pin.json", "vault/portable-keys.json", "vault/receipts.sqlite3"}:
            new_private_file(destination / name, raw)
    new_private_file(destination / "source/receipts.sqlite3", members["vault/receipts.sqlite3"])
    new_private_file(destination / "source/pin.json", members["vault/pin.json"])
    new_private_file(destination / "source/provenance.json", canonical(source_envelope))
    # Portable plaintext DEK is sent straight to the new host's OS wrapper.
    keyset = parse_manifest(bytes(members["vault/portable-keys.json"]))
    key = base64.b64decode(keyset["generations"][0]["key"], validate=True)
    seal_credential(key, destination / "credentials/broker-dek.cred")
    del key, keyset
    with closing(sqlite3.connect(destination / "vault/vault.sqlite3", autocommit=True)) as db:
        db.execute("PRAGMA journal_mode=WAL")
    path = destination / "app/controller.sqlite3"
    with closing(sqlite3.connect(path, autocommit=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        for table in ("reauth", "sessions", "bootstrap"):
            db.execute(f"DELETE FROM {table}")
        if claims["manifest"]["schema"] == 2:
            queue = JobQueue(Store(path))
            last_id = ""
            while jobs := db.execute(
                "SELECT * FROM jobs WHERE id>? AND status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE') ORDER BY id LIMIT 128",
                (last_id,),
            ).fetchall():
                for job in jobs:
                    outcome = "CANCELLED_SAFE" if job["status"] == "QUEUED" else "UNKNOWN_OUTCOME"
                    queue._finish(db, job, outcome, "RESTORE_QUARANTINE")
                    db.execute("UPDATE jobs SET permit=NULL WHERE id=?", (job["id"],))
                last_id = jobs[-1]["id"]
            db.execute("UPDATE resources SET enabled=0")
        Store.event(db, at=int(time.time()), actor=owner_id, kind="recovery.imported", target=request["target_id"],
                    outcome="READ_ONLY_RECOVERY", correlation=request["target_id"], details={"bundle_sha256": bundle_sha256,
                    "source_backup_hash": claims["ciphertext_sha256"], "old_sessions_revoked": True, "automation_disabled": True})
        db.execute("COMMIT")
    for path in destination.rglob("*.sqlite3"):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    result = {"v": 1, "type": "hostorbit.recovery-import", "status": "READ_ONLY_RECOVERY", "target_id": request["target_id"],
              "source_instance": claims["manifest"]["source_instance"], "source_backup_hash": claims["ciphertext_sha256"],
              "bundle_sha256": bundle_sha256, "quarantined_targets": sorted(policy.targets),
              "services_installed": False, "activation": "MANUAL_FENCING_REQUIRED", "restore_verified": False, "backup_gate": "DENIED"}
    new_private_file(destination / "recovery.json", canonical(result))
    directory_sync(destination)
    return result
