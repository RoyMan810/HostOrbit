"""Local console for offline resource restore staging."""

import argparse
import getpass
import os
from pathlib import Path
import sys
import time

from ..errors import Denied
from .archive_stream import AGE_PATH, parse_manifest
from .protocol import canonical, text
from .rescue import harden, offline_profile, wipe
from .rescue_cli import console
from .resource_archive import _NAME, _claims
from .resource_restore_docker import publish_staged_volume
from .resource_restore_stage import stage_restore_source
from .storage import protected_bytes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("ciphertext", "provenance", "trusted-key", "owner-key", "attestation", "evidence", "destination"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--docker-volume", help="Write to a new named volume on a private local Docker daemon")
    parser.add_argument("--application-schema", required=True)
    parser.add_argument("--procedure-sha256", required=True)
    parser.add_argument("--age-tool", type=Path, default=AGE_PATH)
    args = parser.parse_args(argv)
    identity = None
    try:
        harden()
        console()
        offline_profile()
        owner = os.geteuid()
        provenance = parse_manifest(protected_bytes(args.provenance, owner=owner, maximum=65536))
        archive_key = protected_bytes(args.trusted_key, owner=owner, maximum=32)
        claims = _claims(provenance, archive_key)
        if claims["application_schema"] != args.application_schema:
            raise Denied("RESOURCE_ARCHIVE_INCOMPATIBLE")
        owner_key = protected_bytes(args.owner_key, owner=owner, maximum=32)
        attestation = protected_bytes(args.attestation, owner=owner, maximum=65536)
        evidence = protected_bytes(args.evidence, owner=owner, maximum=1024 * 1024)
        print(f"Offline staging destination: {str(args.destination)!r}", file=sys.stderr)
        if args.docker_volume is not None:
            text(args.docker_volume, _NAME, "RESTORE_TARGET_UNTRUSTED")
            print(f"New Docker volume: {args.docker_volume}", file=sys.stderr)
        approved = input("Confirm with the independently verified source ciphertext SHA-256: ").strip()
        if approved != claims["ciphertext_sha256"]:
            raise Denied("RESTORE_STAGE_CONFIRMATION_MISMATCH")
        if args.docker_volume is not None and input("Confirm the exact new Docker volume name: ").strip() != args.docker_volume:
            raise Denied("RESTORE_DOCKER_CONFIRMATION_MISMATCH")
        identity = bytearray(getpass.getpass("Offline Owner age identity: ").strip().encode("ascii") + b"\n")
        result = stage_restore_source(args.ciphertext, provenance, archive_key, identity, destination=args.destination,
                                      attestation=attestation, evidence=evidence, owner_key=owner_key,
                                      application_schema=args.application_schema, procedure_sha256=args.procedure_sha256,
                                      now=int(time.time()), age_path=args.age_tool)
        if args.docker_volume is not None:
            result = publish_staged_volume(args.destination, args.docker_volume, result)
        print(canonical(result).decode())
        return 0
    except Denied as error:
        print(error.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, EOFError):
        print("RESTORE_STAGE_FAILED", file=sys.stderr)
        return 2
    finally:
        if identity is not None:
            wipe(identity)


if __name__ == "__main__":
    raise SystemExit(main())
