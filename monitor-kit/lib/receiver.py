#!/usr/bin/env python3
"""Forced SSH command; invoked with one pre-authorized probe ID."""
import os
import pathlib
import re
import sys
import tempfile
import time

BASE = pathlib.Path('/var/lib/kvpn-monitor/reports')


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,39}', sys.argv[1]):
        raise SystemExit(2)
    probe = sys.argv[1]
    status = sys.stdin.readline(16).strip()
    if status not in ('OK', 'FAIL'):
        raise SystemExit('Invalid status')
    BASE.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix='.' + probe + '.', dir=BASE)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(f'{int(time.time())} {status}\n')
        os.chmod(filename, 0o600)
        os.replace(filename, BASE / (probe + '.status'))
    finally:
        if os.path.exists(filename):
            os.unlink(filename)
    print('STATUS_ACCEPTED')


if __name__ == '__main__':
    main()
