"""Broker-private immutable Vault/receipt copies for one Coordinator snapshot.

No plaintext key is written or returned. A pin is local staging, never a backup
completion/restore proof. There is no pin or secret-export Web/Worker RPC.
"""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import time

from nacl.exceptions import CryptoError

from ..errors import Denied
from .protocol import ULID, canonical, checksum, decode, fields, integer, text
from .storage import Journal, directory_sync, new_private_file, protected_bytes


_MAX_DB = 512 * 1024 * 1024
_MAX_SECRETS = 65536


def capture_with_systemd(snapshot_id):
    """Fixed native helper, isolated from the ordinary synchronous SSH Broker.

    Root Coordinator calls this only after it owns the exclusive barrier. The
    system manager bounds the helper's whole cgroup independently of the caller.
    """
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    text(snapshot_id, ULID)
    from .cli import configuration
    config = configuration(Path("/etc/hostorbit/runtime.json"))
    if "writer_directory" not in config:
        raise Denied("WRITER_CONFIGURATION_REQUIRED")
    from ..admission import Admission
    Admission(config["writer_directory"]).verify_barrier(snapshot_id)
    unit = "hostorbit-pin-" + snapshot_id.lower()
    args = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit,
            "--property=User=" + str(config["broker_uid"]), "--property=Group=" + str(config["broker_gid"]),
            "--property=LoadCredentialEncrypted=broker-dek:" + config["vault_credential"],
            "--property=RuntimeMaxSec=20s", "--property=TimeoutStopSec=1s", "--property=KillMode=control-group",
            "--property=UMask=0077", "--property=LimitCORE=0", "--property=MemoryMax=256M",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=RestrictSUIDSGID=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
            "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=ReadWritePaths=" + config["broker_directory"] + " " + config["vault_directory"],
            "/opt/hostorbit/venv/bin/hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json", "pin-vault", "--snapshot-id", snapshot_id]
    try:
        response = subprocess.run(args, input=b"", capture_output=True, timeout=23,
                                  env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
        if response.returncode or len(response.stdout) > 2048:
            raise Denied("VAULT_PIN_HELPER_FAILED", 503)
        value = decode(response.stdout, canonical_required=False)
        fields(value, ("snapshot_id", "status", "manifest_sha256", "secrets", "objects", "portable_keys_exported", "backup_gate"))
        if (value["snapshot_id"] != snapshot_id or value["status"] != "LOCAL_PIN_ONLY"
                or value["portable_keys_exported"] is not False or value["backup_gate"] != "DENIED"):
            raise Denied("VAULT_PIN_HELPER_FAILED", 503)
        text(value["manifest_sha256"], r"[0-9a-f]{64}")
        integer(value["secrets"], 0, _MAX_SECRETS)
        integer(value["objects"], 0, value["secrets"])
        Admission(config["writer_directory"]).verify_barrier(snapshot_id)
        return value
    except subprocess.TimeoutExpired:
        raise Denied("VAULT_PIN_HELPER_TIMEOUT", 503) from None
    finally:
        # Stop also on parent deadline/SIGINT. RuntimeMaxSec remains independent
        # protection if the Root caller itself is killed before reaching here.
        subprocess.run(["/usr/bin/systemctl", "stop", unit + ".service"], capture_output=True, timeout=2,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})


def _private_directory(path, *, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700)
        directory_sync(path.parent)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Denied("SNAPSHOT_DIRECTORY_INVALID")


def _digest(path, check):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            check()
            digest.update(chunk)
    return digest.hexdigest()


def _copy_database(journal, target, check):
    """Online Backup API copies committed WAL data, not the DB/WAL file pair."""
    new_private_file(target, b"")
    with journal.connect() as source, closing(sqlite3.connect(target, autocommit=True)) as copied:
        source.execute("PRAGMA query_only=ON")
        source.execute("BEGIN")
        source.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        source.backup(copied, pages=64, sleep=0.01, progress=lambda *_: check())
        copied.execute("PRAGMA synchronous=FULL")
        copied.execute("PRAGMA journal_mode=DELETE")

        def progress():
            check()
            return 0

        copied.set_progress_handler(progress, 1000)
        if (copied.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or copied.execute("PRAGMA foreign_key_check").fetchone() is not None
                or copied.execute("PRAGMA user_version").fetchone() != (journal.version,)):
            raise Denied("SNAPSHOT_DATABASE_INVALID")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_sync(Path(target).parent)
    check()


def _metadata(row):
    raw = row["metadata"]
    if not isinstance(raw, str) or len(raw) > 16384:
        raise Denied("VAULT_PIN_METADATA_INVALID")
    try:
        metadata = json.loads(raw)
    except (ValueError, TypeError):
        raise Denied("VAULT_PIN_METADATA_INVALID") from None
    fields(metadata, ("secret_id", "version", "kind", "purpose", "owner_id", "allowed_consumers",
                      "allowed_consumers_digest", "target", "state", "policy_revision", "key_version"))
    for name in ("secret_id", "owner_id", "target"):
        text(metadata[name], ULID)
    integer(metadata["version"], 1, 10**9 - 1)
    integer(metadata["policy_revision"], 1, 2**31 - 1)
    consumers = metadata["allowed_consumers"]
    if (not isinstance(consumers, list) or not 1 <= len(consumers) <= 64
            or any(type(uid) is not int or not 1 <= uid <= 2**31 - 1 for uid in consumers)
            or len(set(consumers)) != len(consumers)):
        raise Denied("VAULT_PIN_METADATA_INVALID")
    if (raw.encode() != canonical(metadata) or row["ref"] != f'{metadata["secret_id"]}:v{metadata["version"]}'
            or row["state"] not in {"ACTIVE", "REVOKED"} or metadata["state"] != "ACTIVE"
            or metadata["kind"] != "ssh.ed25519" or metadata["purpose"] not in {"host.probe", "backup.sftp"}
            or metadata["allowed_consumers_digest"] != checksum(consumers)):
        raise Denied("VAULT_PIN_METADATA_INVALID")
    # Runtime Vault currently has one working generation. Silently omitting an
    # older/unknown generation would create a non-portable, unrestorable archive.
    if type(metadata["key_version"]) is not int or metadata["key_version"] != 1:
        raise Denied("VAULT_PIN_KEY_GENERATION_UNSUPPORTED")
    return metadata


def pin_vault(vault, broker_directory, admission, snapshot_id, *, timeout=25):
    """Called by a separate Broker-UID helper while Root holds the short barrier."""
    text(snapshot_id, ULID)
    if not 0 < timeout <= 25:
        raise ValueError("SNAPSHOT_DEADLINE_INVALID")
    until = time.monotonic() + timeout

    def check():
        if time.monotonic() >= until:
            raise Denied("VAULT_PIN_TIMEOUT", 503)
        admission.verify_barrier(snapshot_id)

    check()
    broker_directory = Path(broker_directory)
    _private_directory(broker_directory)
    _private_directory(vault.directory)
    _private_directory(vault.directory / "objects")
    receipts = Journal(broker_directory / "receipts.sqlite3")
    database_sizes = []
    for journal in (vault.journal, receipts):
        with journal.connect() as db:
            size = db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
            if size > _MAX_DB:
                raise Denied("VAULT_PIN_SIZE_UNSUPPORTED")
            database_sizes.append(size)
    with vault.journal.connect() as db:
        count = db.execute("SELECT count(*) FROM secrets").fetchone()[0]
        if count > _MAX_SECRETS:
            raise Denied("VAULT_PIN_SIZE_UNSUPPORTED")
    # Count committed logical pages, including pages still in WAL, and reserve
    # the largest supported object per reference plus metadata space.
    required = sum(database_sizes) + count * 9000 + 64 * 1024 * 1024
    if shutil.disk_usage(broker_directory).free < required:
        raise Denied("VAULT_PIN_SPACE_INSUFFICIENT", 503)
    parent = broker_directory / "snapshot-pins"
    if not os.path.lexists(parent):
        _private_directory(parent, create=True)
    _private_directory(parent)
    target = parent / snapshot_id
    _private_directory(target, create=True)
    _private_directory(target / "objects", create=True)
    _copy_database(vault.journal, target / "vault.sqlite3", check)
    _copy_database(receipts, target / "receipts.sqlite3", check)
    references, objects = [], set()
    with closing(sqlite3.connect((target / "vault.sqlite3").as_uri() + "?mode=ro", uri=True, autocommit=True)) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute("SELECT * FROM secrets ORDER BY ref"):
            check()
            metadata = _metadata(row)
            digest = text(row["object_digest"], r"[0-9a-f]{64}")
            ciphertext = protected_bytes(vault.directory / "objects" / digest, owner=os.geteuid(), maximum=9000, exact_mode=0o600)
            if hashlib.sha256(ciphertext).hexdigest() != digest:
                raise Denied("VAULT_PIN_OBJECT_CORRUPT")
            try:
                # Authentication also covers revoked versions; their state is
                # preserved without granting Use on a revoked secret.
                plaintext = vault._aead.decrypt(ciphertext, canonical(metadata))
            except CryptoError:
                raise Denied("VAULT_PIN_OBJECT_CORRUPT") from None
            if not 100 <= len(plaintext) <= 8192:
                raise Denied("VAULT_PIN_OBJECT_CORRUPT")
            del plaintext
            if digest not in objects:
                new_private_file(target / "objects" / digest, ciphertext)
                objects.add(digest)
            references.append({"ref": row["ref"], "state": row["state"], "object_digest": digest,
                               "metadata_sha256": checksum(metadata), "key_generation": 1})
    files = []
    for path in (target / "vault.sqlite3", target / "receipts.sqlite3", *(target / "objects" / digest for digest in sorted(objects))):
        check()
        files.append({"path": str(path.relative_to(target)), "size": path.stat().st_size, "sha256": _digest(path, check)})
    value = {"v": 1, "type": "vault.pin", "snapshot_id": snapshot_id, "key_generations": [1],
             "key_fingerprints": {"1": hashlib.sha256(bytes(vault._aead)).hexdigest()}, "references": references, "files": files}
    check()
    try:
        new_private_file(target / "pin.json", canonical(value))
        check()
    except BaseException:
        (target / "pin.json").unlink(missing_ok=True)
        directory_sync(target)
        raise
    return {"snapshot_id": snapshot_id, "status": "LOCAL_PIN_ONLY", "manifest_sha256": checksum(value),
            "secrets": len(references), "objects": len(objects), "portable_keys_exported": False, "backup_gate": "DENIED"}
