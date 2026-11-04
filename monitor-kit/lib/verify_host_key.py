#!/usr/bin/env python3
"""Validate *every* ssh-keyscan Ed25519 key against an out-of-band fingerprint.

Use only Python's standard library so the helper is usable on minimal Ubuntu.
Never write an unverified entry into SSH known_hosts.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path
import re
import struct
import sys


class HostKeyError(ValueError):
    pass


def fingerprint_for_key(encoded_key: str) -> str:
    """Return the OpenSSH SHA256 fingerprint of a well-formed Ed25519 key blob."""
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HostKeyError("Invalid base64 in SSH host key") from exc
    # RFC 4253 SSH wire format: string("ssh-ed25519"), string(32-byte public key).
    if len(key) != 51 or key[:4] != struct.pack(">I", 11) or key[4:15] != b"ssh-ed25519" or key[15:19] != struct.pack(">I", 32):
        raise HostKeyError("Malformed Ed25519 SSH host key")
    digest = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def verify_scan(contents: str, expected: str) -> int:
    """Reject malformed, non-Ed25519 and mismatched keys, including *later* rows."""
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected):
        raise HostKeyError("Invalid expected Ed25519 SHA256 fingerprint")
    count = 0
    for row in contents.splitlines():
        if not row.strip() or row.startswith("#"):
            continue
        fields = row.split()
        if len(fields) != 3 or fields[1] != "ssh-ed25519" or not fields[0]:
            raise HostKeyError("Unexpected ssh-keyscan entry")
        actual = fingerprint_for_key(fields[2])
        if actual != expected:
            raise HostKeyError("Panel host key fingerprint mismatch; refusing to trust this scan")
        count += 1
    if not count:
        raise HostKeyError("No verified Ed25519 SSH host keys in scan")
    return count


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: verify_host_key.py KEYSCAN_FILE VERIFIED_SHA256", file=sys.stderr)
        return 2
    try:
        number = verify_scan(Path(sys.argv[1]).read_text(encoding="ascii"), sys.argv[2])
    except (HostKeyError, OSError, UnicodeError) as exc:
        print(f"Panel SSH host key verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"Verified {number} SSH Ed25519 host key(s) against the supplied fingerprint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
