#!/usr/bin/env bash
warn() { printf '\nWARNING: %s\n' "$*" >&2; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ "$(id -u)" -eq 0 ]] || die 'Run as root: sudo ./install.sh ...'; }
confirm() {
  local answer
  if [[ -r /dev/tty ]]; then
    read -r -p "$1 [yes/no] " answer < /dev/tty
  else
    die 'Interactive terminal required to approve changes'
  fi
  [[ "$answer" == yes ]]
}
ask_default() {
  local prompt="$1" default="$2" result
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " result < /dev/tty
  else
    read -r -p "$prompt: " result < /dev/tty
  fi
  printf '%s' "${result:-$default}"
}
valid_ipv4() {
  python3 - "$1" <<'PY'
import ipaddress,sys
try:
 ipaddress.IPv4Address(sys.argv[1]); sys.exit(0)
except ValueError: sys.exit(1)
PY
}
valid_ip_or_cidr() {
  python3 - "$1" <<'PY'
import ipaddress,sys
try:
 ipaddress.IPv4Network(sys.argv[1],strict=False); sys.exit(0)
except ValueError: sys.exit(1)
PY
}
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
