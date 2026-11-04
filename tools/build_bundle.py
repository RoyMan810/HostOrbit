#!/usr/bin/env python3
"""Build or check deterministic single-file installer from tracked runtime sources.

Usage: python3 tools/build_bundle.py [--check]
The embedded archive intentionally excludes tests, docs and kvpn-install.sh itself.
"""
import argparse
import base64
import gzip
import io
from pathlib import Path
import tarfile
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    'install.sh',
    'lib/common.sh', 'lib/tui.sh', 'lib/backup-node.sh',
    'lib/textual_protocol.sh', 'lib/textual_launcher.sh', 'lib/textual_ui.py',
    'monitor-kit/install.sh',
    'monitor-kit/lib/monitor.py', 'monitor-kit/lib/receiver.py',
    'monitor-kit/lib/register.py', 'monitor-kit/lib/sender.sh',
)
BOOTSTRAP = r'''#!/usr/bin/env bash
# K-VPN Node Deployer — self-extracting installer (built from tools/build_bundle.py).
set -Eeuo pipefail
umask 077
missing=()
for binary in base64 tar gzip awk tail mktemp; do
  command -v "$binary" >/dev/null 2>&1 || missing+=("$binary")
done
if (( ${#missing[@]} > 0 )); then
  printf 'Не хватает утилит для распаковки: %s\n' "${missing[*]}" >&2
  if [[ "$(id -u)" -eq 0 && -r /dev/tty ]] && command -v apt-get >/dev/null 2>&1; then
    printf 'Установить системные утилиты из APT? [yes/no] ' > /dev/tty
    read -r answer < /dev/tty || exit 1
    if [[ "$answer" == yes ]]; then
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends coreutils tar gzip mawk
    fi
  fi
  for binary in base64 tar gzip awk tail mktemp; do
    command -v "$binary" >/dev/null 2>&1 || { echo "Не хватает утилиты: $binary" >&2; exit 1; }
  done
fi
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
payload_line=$(awk '/^__KVPN_INSTALL_PAYLOAD_BELOW__$/{print NR+1;exit}' "$0")
[[ -n "$payload_line" ]] || { echo 'Повреждённый установщик: нет архива' >&2; exit 1; }
tail -n "+$payload_line" "$0" | base64 -d | tar -xz -C "$tmp" --no-same-owner
bash "$tmp/kvpn-node-deployer/install.sh" "$@"
exit $?
__KVPN_INSTALL_PAYLOAD_BELOW__
'''


def render():
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w', format=tarfile.USTAR_FORMAT) as tf:
        for name in RUNTIME:
            path = ROOT / name
            data = path.read_bytes()
            info = tarfile.TarInfo('kvpn-node-deployer/' + name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = 'root'
            info.mode = 0o755 if path.suffix == '.sh' or path.name == 'receiver.py' else 0o644
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    packed = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=packed, mode='wb', mtime=0, compresslevel=9) as gz:
        gz.write(content.getvalue())
    encoded = base64.b64encode(packed.getvalue()).decode('ascii')
    return BOOTSTRAP + ''.join(encoded[i:i+76] + '\n' for i in range(0, len(encoded), 76))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    expected = render()
    destination = ROOT / 'kvpn-install.sh'
    if args.check:
        if not destination.exists() or destination.read_text() != expected:
            print('ERROR: kvpn-install.sh out of sync; run python3 tools/build_bundle.py', file=sys.stderr)
            return 1
        print('Single-file installer is reproducible and up to date')
        return 0
    destination.write_text(expected)
    destination.chmod(0o755)
    print(f'Built {destination.name} ({destination.stat().st_size} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
