"""Local-console-only Rescue entry point; no HTTP/RPC secret interface."""

import argparse
import getpass
import os
from pathlib import Path
import sys
import sqlite3
import subprocess

from ..errors import Denied
from .archive_stream import AGE_KEYGEN_PATH, AGE_PATH, parse_manifest
from .protocol import canonical
from .recovery_import import RecoveryTarget
from .rescue import harden, offline_profile, prepare_bundle, wipe
from .resource_archive import verify_archive
from .storage import protected_bytes


def console():
    # No stdin/password-file/env/argv fallback. A caller must use an authenticated
    # local Rescue terminal, independent of the uploaded bundle/WebUI.
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise Denied("RESCUE_TRUSTED_CONSOLE_REQUIRED")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hostorbit-rescue")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    request = sub.add_parser("request")
    request.add_argument("--state", type=Path, required=True)
    request.add_argument("--destination", type=Path, required=True)
    request.add_argument("--source-envelope-sha256", required=True)
    request.add_argument("--keygen-tool", type=Path, default=AGE_KEYGEN_PATH)
    pack = sub.add_parser("repackage")
    for flag in ("ciphertext", "provenance", "trusted-key", "request", "output"):
        pack.add_argument("--" + flag, type=Path, required=True)
    pack.add_argument("--age-tool", type=Path, default=AGE_PATH)
    resource = sub.add_parser("verify-resource-archive", help="Verify a stopped Docker named-volume archive offline")
    for flag in ("ciphertext", "provenance", "trusted-key"):
        resource.add_argument("--" + flag, type=Path, required=True)
    resource.add_argument("--application-schema", required=True)
    resource.add_argument("--age-tool", type=Path, default=AGE_PATH)
    accept = sub.add_parser("import")
    accept.add_argument("--state", type=Path, required=True)
    accept.add_argument("--bundle", type=Path, required=True)
    accept.add_argument("--age-tool", type=Path, default=AGE_PATH)
    args = parser.parse_args(argv)
    identity = None
    try:
        harden()
        if args.command == "preflight":
            result = offline_profile()
        else:
            console()
            if args.command == "request":
                result = RecoveryTarget.issue(args.state, args.destination, args.source_envelope_sha256, keygen_path=args.keygen_tool)
            elif args.command in ("repackage", "verify-resource-archive"):
                offline_profile()  # Refuse the workstation before asking for secrets.
                is_resource = args.command == "verify-resource-archive"
                envelope = parse_manifest(protected_bytes(args.provenance, owner=os.geteuid(), maximum=65536))
                anchor = protected_bytes(args.trusted_key, owner=os.geteuid(), maximum=32)
                if not is_resource:
                    request = parse_manifest(protected_bytes(args.request, owner=os.geteuid()))
                identity = bytearray(getpass.getpass("Offline Owner age identity: ").strip().encode("ascii") + b"\n")
                if is_resource:
                    result = verify_archive(args.ciphertext, envelope, anchor, identity,
                                            application_schema=args.application_schema, age_path=args.age_tool)
                else:
                    result = prepare_bundle(args.ciphertext, envelope, anchor, identity, request, args.output, age_path=args.age_tool)
            else:
                target = RecoveryTarget(args.state, age_path=args.age_tool)
                digest = input("Exact SHA-256 from the offline workstation (independent confirmation): ").strip()
                username = input("Source Owner username: ").strip()
                password = getpass.getpass("Source Owner password: ")
                try:
                    result = target.accept(args.bundle, owner_digest=digest, username=username, password=password)
                finally:
                    del password
        print(canonical(result).decode())
        return 0
    except Denied as error:
        print(error.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error, subprocess.SubprocessError):
        print("RESCUE_FAILED", file=sys.stderr)
        return 2
    finally:
        if identity is not None:
            wipe(identity)


if __name__ == "__main__":
    raise SystemExit(main())
