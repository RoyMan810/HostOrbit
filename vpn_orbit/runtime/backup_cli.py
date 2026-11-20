"""Root-only archive creation and public-anchor provenance verification."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from ..errors import Denied
from .archive_stream import parse_manifest
from .controller_backup import ControllerBackup, verify_provenance


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vpn-orbit-backup")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Root local signed archive; no off-host completion/Backup Gate")
    create.add_argument("--recipient", required=True, help="Owner public native age X25519 recipient; never a private identity")
    publication = commands.add_parser("publish", help="Root publication of an existing signed snapshot to the protected SFTP target")
    publication.add_argument("--snapshot-id", required=True)
    verify = commands.add_parser("verify", help="Verify ciphertext/provenance using an independently saved public anchor")
    verify.add_argument("--ciphertext", type=Path, required=True)
    verify.add_argument("--provenance", type=Path, required=True)
    verify.add_argument("--trusted-key", type=Path, required=True)
    inventory = commands.add_parser("retention-inventory", help="List Controller snapshots and optional signed local volume archives")
    inventory.add_argument("--resource-directory", type=Path, action="append", help="One signed volume capture directory (repeatable)")
    inventory.add_argument("--resource-trusted-key", type=Path)
    for name in ("retention-review", "retire-local"):
        command = commands.add_parser(name, help="Review or release one registered local Controller ciphertext")
        command.add_argument("--snapshot-id", required=True)
        command.add_argument("--keep-id", required=True)
        command.add_argument("--evidence", type=Path, required=True)
        if name == "retire-local":
            command.add_argument("--approval", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command != "verify":
            import os
            if os.geteuid() != 0:
                raise Denied("LOCAL_ROOT_REQUIRED")
            from .cli import configuration
            config = configuration(Path("/etc/vpn-orbit/runtime.json"))
            if args.command == "create":
                result = ControllerBackup(config).create(args.recipient)
            elif args.command == "publish":
                from .publication import Publisher
                result = Publisher(config).publish(args.snapshot_id)
            else:
                from .retention import Retention, resource_inventory
                retention = Retention(config)
                if args.command == "retention-inventory":
                    if bool(args.resource_directory) != bool(args.resource_trusted_key):
                        raise Denied("RESOURCE_ARCHIVE_ANCHOR_REQUIRED")
                    result = {"controller": retention.inventory()}
                    if args.resource_directory:
                        result["resource"] = [resource_inventory(directory, args.resource_trusted_key, 0)
                                              for directory in args.resource_directory]
                elif args.command == "retention-review":
                    result = retention.review(args.snapshot_id, args.keep_id, args.evidence)
                else:
                    result = retention.retire(args.snapshot_id, args.keep_id, args.evidence, args.approval)
        else:
            with args.provenance.open("rb") as stream:
                envelope = parse_manifest(stream.read(16385))
            with args.trusted_key.open("rb") as stream:
                key = stream.read(33)
            if len(key) != 32:
                raise Denied("ARCHIVE_PROVENANCE_INVALID")
            claims = verify_provenance(args.ciphertext, envelope, key)
            result = {"status": "PROVENANCE_VERIFIED", "snapshot_id": claims["manifest"]["snapshot_id"],
                      "payload_integrity": "NOT_DECRYPTED", "restore_verified": False, "backup_gate": "DENIED"}
        print(json.dumps(result))
        return 0
    except (Denied, OSError, ValueError, RuntimeError, sqlite3.Error, TypeError, KeyError) as error:
        print(error.code if isinstance(error, Denied) else "BACKUP_STORAGE_OR_SERVICE_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
