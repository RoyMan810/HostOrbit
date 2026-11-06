#!/usr/bin/python3 -I
"""Root-side allowlist for a read-only Stage 0 probe."""

import os
import signal
import sys


_REQUEST = b'{"operation":"probe","target":"stage0-fixture","version":1}\n'


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        return 65
    signal.alarm(5)
    payload = sys.stdin.buffer.read(len(_REQUEST) + 1)
    signal.alarm(0)
    if payload != _REQUEST:
        return 65
    print('{"status":"OK","uid":0,"version":1}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
