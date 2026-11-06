#!/usr/bin/python3 -I
"""Forced command for the Stage 0 restricted SSH fixture."""

import os
import signal
import subprocess
import sys


_REQUEST = b'{"operation":"probe","target":"stage0-fixture","version":1}\n'
_HELPER = "/usr/local/libexec/hostorbit/typed-helper"


def forward(command: str, request: bytes, *, timeout: int = 5) -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND") != command:
        return 65
    signal.alarm(5)
    payload = sys.stdin.buffer.read(len(request) + 1)
    signal.alarm(0)
    if payload != request:
        return 65
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "--", _HELPER],
            input=payload, timeout=timeout, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return 70
    return result.returncode


def main() -> int:
    return forward("hostorbit.stage0.probe", _REQUEST)


if __name__ == "__main__":
    raise SystemExit(main())
