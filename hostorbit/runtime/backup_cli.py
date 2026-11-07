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
    parser = argparse.ArgumentParser(prog="hostorbit-backup")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Root local signed archive; no off-host completion/Backup Gate")
    create.add_argument("--recipient", required=True, help="Owner public native age X25519 recipient; never a private identity")
    verify = commands.add_parser("verify", help="Verify ciphertext/provenance using an independently saved public anchor")
    verify.add_argument("--ciphertext", type=Path, required=True)
    verify.add_argument("--provenance", type=Path, required=True)
    verify.add_argument("--trusted-key", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            import os
            if os.geteuid() != 0:
                raise Denied("LOCAL_ROOT_REQUIRED")
            from .cli import configuration
            result = ControllerBackup(configuration(Path("/etc/hostorbit/runtime.json"))).create(args.recipient)
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
