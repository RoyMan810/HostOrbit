"""Bounded, memory-only verification of the production Controller age payload.

No tar extraction, SQLite temporary database, executable archive content or
source OS credential is used. Only the current portable generation is supported.
"""

import base64
from contextlib import contextmanager
import hashlib
import io
import sqlite3
import tarfile
import time

from nacl.exceptions import CryptoError
from nacl.secret import Aead

from ..database import Store
from ..errors import Denied
from ..migrations import expected_schema, schema_rows
from .archive_stream import MAX_PAYLOAD, MAX_RECOVERY_MEMBERS, parse_manifest, validate_source
from .pins import _metadata
from .protocol import SHA256, canonical, checksum, fields, integer, text


def unpack(raw):
    """Accept only the exact deterministic USTAR dialect written by Broker.

    Parsing headers ourselves avoids PAX/GNU extension processing, sparse files,
    aliases and tarfile's implicit skipping of duplicate/trailing members.
    Values are views of the caller's wipeable buffer, never disk files.
    """
    if not 10240 <= len(raw) <= MAX_PAYLOAD or len(raw) % 10240:
        raise Denied("RESCUE_TAR_INVALID")
    view, offset, members = memoryview(raw), 0, {}
    while offset + 512 <= len(raw):
        header = bytes(view[offset:offset + 512])
        if header == bytes(512):
            if len(raw) - offset < 1024 or any(view[offset:]):
                raise Denied("RESCUE_TAR_INVALID")
            return members
        try:
            info = tarfile.TarInfo.frombuf(header, "ascii", "strict")
            expected = tarfile.TarInfo(info.name)
            expected.mode, expected.size = 0o600, info.size
            # Reject even semantically equivalent encodings or extra metadata.
            if (header != expected.tobuf(tarfile.USTAR_FORMAT, "ascii", "strict")
                    or info.type != tarfile.REGTYPE or info.name in members
                    or info.name.startswith("/") or any(p in {"", ".", ".."} for p in info.name.split("/"))
                    or not 0 < info.size <= MAX_PAYLOAD or len(members) >= MAX_RECOVERY_MEMBERS):
                raise ValueError()
        except (ValueError, UnicodeError, tarfile.HeaderError):
            raise Denied("RESCUE_TAR_INVALID") from None
        start, end = offset + 512, offset + 512 + info.size
        padded = (end + 511) // 512 * 512
        if padded > len(raw) or any(view[end:padded]):
            raise Denied("RESCUE_TAR_INVALID")
        members[info.name] = view[start:end]
        offset = padded
    raise Denied("RESCUE_TAR_INVALID")


@contextmanager
def database(raw, version, *, schema=None):
    if (len(raw) < 100 or bytes(raw[:16]) != b"SQLite format 3\x00"
            or bytes(raw[18:20]) != b"\x01\x01"):
        raise Denied("RESCUE_DATABASE_INVALID")
    db = sqlite3.connect(":memory:", autocommit=True)
    until = time.monotonic() + 30
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_PAYLOAD)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
        db.deserialize(raw)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA query_only=ON")
        db.set_progress_handler(lambda: int(time.monotonic() >= until), 1000)
        if (db.execute("PRAGMA user_version").fetchone() != (version,)
                or db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or db.execute("PRAGMA foreign_key_check").fetchone() is not None
                or db.execute("SELECT 1 FROM sqlite_schema WHERE type='view'").fetchone()):
            raise Denied("RESCUE_DATABASE_INVALID")
        db.row_factory = sqlite3.Row
        if schema is not None and schema_rows(db) != schema:
            raise Denied("RESCUE_SCHEMA_DRIFT")
        yield db
    except sqlite3.Error:
        raise Denied("RESCUE_DATABASE_INVALID") from None
    finally:
        db.close()


def _match(members, prefix, records):
    names = set()
    for record in records:
        fields(record, ("path", "size", "sha256"))
        name = prefix + record["path"]
        integer(record["size"], 1, MAX_PAYLOAD)
        text(record["sha256"], SHA256)
        if (name in names or name not in members or len(members[name]) != record["size"]
                or hashlib.sha256(members[name]).hexdigest() != record["sha256"]):
            raise Denied("RESCUE_MEMBER_CHANGED")
        names.add(name)
    return names


def verify(members, claims, trusted_key):
    from .authority import _SCHEMA as gate_schema
    from .broker import _SCHEMA as receipts_schema
    from .vault import _SCHEMA as vault_schema

    def runtime_schema(script):
        db = sqlite3.connect(":memory:")
        try:
            db.executescript(script)
            return schema_rows(db)
        finally:
            db.close()

    manifest = parse_manifest(bytes(members.get("controller/manifest.json", b"")))
    validate_source(manifest, claims["manifest"]["snapshot_id"])
    if manifest != claims["manifest"] or bytes(members.get("controller/gate.pub", b"")) != trusted_key:
        raise Denied("RESCUE_SOURCE_CHANGED")
    expected = {"controller/manifest.json", "vault/pin.json", "vault/portable-keys.json"}
    expected |= _match(members, "controller/", manifest["files"])
    pin_raw = bytes(members.get("vault/pin.json", b""))
    if hashlib.sha256(pin_raw).hexdigest() != manifest["pin_sha256"]:
        raise Denied("RESCUE_PIN_CHANGED")
    pin = fields(parse_manifest(pin_raw), ("v", "type", "snapshot_id", "key_generations", "key_fingerprints", "references", "files"))
    if (type(pin["v"]) is not int or pin["v"] != 1 or pin["type"] != "vault.pin"
            or pin["snapshot_id"] != manifest["snapshot_id"] or pin["key_generations"] != [1]
            or not isinstance(pin["references"], list) or len(pin["references"]) > 65536
            or not isinstance(pin["files"], list)):
        raise Denied("RESCUE_PIN_INVALID")
    keyset = fields(parse_manifest(bytes(members["vault/portable-keys.json"])), ("v", "type", "generations"))
    if (type(keyset["v"]) is not int or keyset["v"] != 1 or keyset["type"] != "hostorbit.portable-keyset"
            or not isinstance(keyset["generations"], list) or len(keyset["generations"]) != 1):
        raise Denied("RESCUE_KEYSET_UNSUPPORTED")
    generation = fields(keyset["generations"][0], ("version", "key"))
    try:
        key = base64.b64decode(generation["key"], validate=True)
    except (ValueError, TypeError):
        raise Denied("RESCUE_KEYSET_INVALID") from None
    if (type(generation["version"]) is not int or generation["version"] != 1 or len(key) != 32
            or pin["key_fingerprints"] != {"1": hashlib.sha256(key).hexdigest()}):
        raise Denied("RESCUE_KEYSET_INVALID")
    aead = Aead(key)
    del key, keyset, generation
    expected |= _match(members, "vault/", pin["files"])
    vault_names = {"vault.sqlite3", "receipts.sqlite3"}
    references = []
    with database(members["vault/vault.sqlite3"], 1, schema=runtime_schema(vault_schema)) as db:
        for row in db.execute("SELECT * FROM secrets ORDER BY ref"):
            metadata = _metadata(row)
            digest = text(row["object_digest"], SHA256)
            vault_names.add("objects/" + digest)
            encrypted = members.get("vault/objects/" + digest)
            if encrypted is None or len(encrypted) > 9000 or hashlib.sha256(encrypted).hexdigest() != digest:
                raise Denied("RESCUE_VAULT_INCOMPLETE")
            try:
                secret = aead.decrypt(bytes(encrypted), canonical(metadata))
                if not 100 <= len(secret) <= 8192:
                    raise Denied("RESCUE_VAULT_INVALID")
                del secret
            except CryptoError:
                raise Denied("RESCUE_VAULT_INVALID") from None
            references.append({"ref": row["ref"], "state": row["state"], "object_digest": digest,
                               "metadata_sha256": checksum(metadata), "key_generation": 1})
    if references != pin["references"] or vault_names != {record["path"] for record in pin["files"]}:
        raise Denied("RESCUE_VAULT_INCOMPLETE")
    del aead
    if set(members) != expected:
        raise Denied("RESCUE_SCOPE_INVALID")
    with database(members["controller/app.sqlite3"], manifest["schema"], schema=expected_schema(manifest["schema"])) as db:
        if (Store.verify_audit_connection(db) != manifest["audit_head"]
                or db.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0] != manifest["audit_sequence"]
                or db.execute("SELECT count(*) FROM users WHERE role='Owner' AND disabled=0").fetchone()[0] != 1):
            raise Denied("RESCUE_APPLICATION_INVALID")
    with database(members["controller/gate.sqlite3"], 1, schema=runtime_schema(gate_schema)) as db:
        gate = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
        if gate is None or gate["instance_id"] != manifest["source_instance"] or gate["epoch"] != manifest["gate_epoch"]:
            raise Denied("RESCUE_GATE_INVALID")
    with database(members["vault/receipts.sqlite3"], 1, schema=runtime_schema(receipts_schema)):
        pass
    from .policy import Policy
    policy_value = fields(parse_manifest(bytes(members["controller/targets.json"])), ("v", "targets"))
    if type(policy_value["v"]) is not int or policy_value["v"] != 1 or not isinstance(policy_value["targets"], list):
        raise Denied("RESCUE_POLICY_INVALID")
    policy = Policy(policy_value["targets"])
    if policy.digest != gate["policy_digest"] or any(t.value["secret_ref"] not in {r["ref"] for r in references} for t in policy.targets.values()):
        raise Denied("RESCUE_POLICY_INVALID")
    if "controller/backup-target.json" in members:
        from .backup_target import BackupTarget
        destination = BackupTarget.parse(parse_manifest(bytes(members["controller/backup-target.json"])))
        if destination is not None and destination.value["secret_ref"] not in {r["ref"] for r in references}:
            raise Denied("RESCUE_POLICY_INVALID")
    return {"schema": manifest["schema"], "snapshot_id": manifest["snapshot_id"], "audit_head": manifest["audit_head"],
            "audit_sequence": manifest["audit_sequence"], "members": len(members), "secret_versions": len(references),
            "key_generations": [1], "source_commit": manifest["source_commit"], "source_instance": manifest["source_instance"]}


def write_tar(output, members):
    from .archive_stream import _member
    with tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in members.items():
            _member(tar, name, io.BytesIO(raw), len(raw))
