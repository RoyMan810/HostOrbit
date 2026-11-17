"""Check recorded backup publication and freshness before a migration."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

from ..errors import Denied
from .archive_stream import parse_manifest, private_stream
from .authority import host_binding
from .backup_target import BackupTarget
from .clock import NANOSECOND, clocks
from .controller_backup import ControllerBackup, verify_provenance_claims
from .pins import _private_directory
from .protocol import ULID, canonical, checksum, text
from .publication import TARGET_PATH
from .sftp_publication import completion
from .storage import protected_bytes


def _check_downloaded_copy(directory, marker, provenance, claims, owner):
    directory = Path(directory)
    _private_directory(directory)
    expected = {
        "COMPLETE": (len(marker), hashlib.sha256(marker).hexdigest()),
        "provenance.json": (len(provenance), hashlib.sha256(provenance).hexdigest()),
        "controller.age": (claims["ciphertext_size"], claims["ciphertext_sha256"]),
    }
    if {path.name for path in directory.iterdir()} != expected.keys():
        raise Denied("MIGRATION_BACKUP_COPY_INCOMPLETE")

    for name, (size, digest) in expected.items():
        try:
            with private_stream(directory / name, owner) as (stream, actual_size):
                if actual_size != size:
                    raise Denied("MIGRATION_BACKUP_COPY_MISMATCH")
                hasher = hashlib.sha256()
                remaining = size
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        break
                    hasher.update(chunk)
                    remaining -= len(chunk)
                if remaining or stream.read(1) or hasher.hexdigest() != digest:
                    raise Denied("MIGRATION_BACKUP_COPY_MISMATCH")
        except OSError:
            raise Denied("MIGRATION_BACKUP_COPY_UNSAFE") from None
        except Denied as error:
            if error.code != "ARCHIVE_FILE_INVALID":
                raise
            raise Denied("MIGRATION_BACKUP_COPY_UNSAFE") from None


def check_publication(config, snapshot_id, *, downloaded_copy=None, target_path=TARGET_PATH, owner=0):
    """Return point-in-time publication evidence without granting a permit."""
    if os.geteuid() != owner:
        raise Denied("LOCAL_ROOT_REQUIRED")
    text(snapshot_id, ULID)
    backup = ControllerBackup(config, owner=owner)
    target = BackupTarget.load(target_path, owner=owner)
    if target is None:
        raise Denied("BACKUP_TARGET_DISABLED")

    directory = backup.coordinator.directory / "captures" / snapshot_id
    _private_directory(directory.parent)
    _private_directory(directory)
    provenance = protected_bytes(directory / "provenance.json", owner=owner, exact_mode=0o600)
    key = protected_bytes(config["public_verify_key"], owner=owner, maximum=32)
    envelope = parse_manifest(provenance)
    claims = verify_provenance_claims(envelope, key)
    manifest = claims["manifest"]
    gate = backup.gate_row()
    with backup.store.connect(readonly=True) as db:
        schema = db.execute("PRAGMA user_version").fetchone()[0]
    if (manifest["snapshot_id"] != snapshot_id or manifest["source_instance"] != gate["instance_id"]
            or gate["host_binding"] != host_binding() or manifest["schema"] != schema):
        raise Denied("MIGRATION_BACKUP_SOURCE_MISMATCH")

    with backup.coordinator.journal.connect() as db:
        barrier = db.execute(
            "SELECT t.boot_id,t.monotonic_ns FROM snapshots s JOIN transitions t ON t.snapshot_id=s.id "
            "WHERE s.id=? AND s.phase='PUBLISHED' AND t.phase='SHORT_BARRIER'",
            (snapshot_id,),
        ).fetchone()
    if barrier is None:
        raise Denied("MIGRATION_PUBLICATION_NOT_RECORDED")

    marker = completion(target, snapshot_id, claims, provenance)
    receipt = {**marker, "marker_sha256": checksum(marker),
               "remote_path": target.value["directory"] + "/" + snapshot_id, "verified": True}
    recorded = protected_bytes(directory / "publication-receipt.json", owner=owner, exact_mode=0o600)
    if recorded != canonical(receipt):
        raise Denied("MIGRATION_PUBLICATION_BINDING_INVALID")

    if downloaded_copy is not None:
        _check_downloaded_copy(downloaded_copy, canonical(marker), provenance, claims, owner)

    now = clocks()
    if (barrier["boot_id"] != manifest["boot_id"] or manifest["boot_id"] != now["boot_id"]
            or not 0 <= barrier["monotonic_ns"] <= manifest["monotonic_ns"] <= now["mono_ns"]):
        raise Denied("MIGRATION_BACKUP_CLOCK_UNVERIFIED")
    # BOOTTIME includes suspension while the journal's MONOTONIC does not.
    # This bounds the age from above, including any suspend before the barrier.
    age = now["tick_ns"] - barrier["monotonic_ns"]
    if not 0 <= age <= 1800 * NANOSECOND:
        raise Denied("MIGRATION_BACKUP_STALE")
    status = "FRESH_BACKUP_COPY_VERIFIED" if downloaded_copy is not None else "FRESH_PUBLICATION_RECORDED"
    return {"status": status, "snapshot_id": snapshot_id,
            "source_instance": gate["instance_id"], "source_schema": schema, "target_id": target.value["id"],
            "marker_sha256": receipt["marker_sha256"], "maximum_age_seconds": (age + NANOSECOND - 1) // NANOSECOND,
            "failure_domain_verified": False, "restore_verified": False, "backup_gate": "DENIED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check recorded publication and optionally verify a downloaded ControllerBackup")
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--downloaded-copy", type=Path, help="Private directory with the three completed SFTP files")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Denied("LOCAL_ROOT_REQUIRED")
        from .cli import configuration
        config = configuration(Path("/etc/hostorbit/runtime.json"))
        print(json.dumps(check_publication(config, args.snapshot_id, downloaded_copy=args.downloaded_copy)))
        return 0
    except (Denied, OSError, ValueError, RuntimeError, sqlite3.Error, TypeError, KeyError) as error:
        print(error.code if isinstance(error, Denied) else "BACKUP_STORAGE_OR_SERVICE_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
