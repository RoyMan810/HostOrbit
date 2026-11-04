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
  [[ -r /dev/tty ]] || die 'Interactive terminal required for wizard'
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " result < /dev/tty || die 'Could not read input'
  else
    read -r -p "$prompt: " result < /dev/tty || die 'Could not read input'
  fi
  printf '%s' "${result:-$default}"
}
valid_ipv4() {
  # This must work before Python is installed on minimal Ubuntu images.
  local ip="${1:-}" octet
  local -a parts
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<< "$ip"
  [[ ${#parts[@]} -eq 4 ]] || return 1
  for octet in "${parts[@]}"; do
    [[ ${#octet} -le 3 ]] || return 1
    [[ ${#octet} -eq 1 || "${octet:0:1}" != 0 ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
valid_ip_or_cidr() {
  local value="${1:-}" ip prefix
  if [[ "$value" == */* ]]; then
    ip="${value%%/*}"; prefix="${value#*/}"
    valid_ipv4 "$ip" || return 1
    [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1
    (( 10#$prefix <= 32 )) || return 1
  else
    valid_ipv4 "$value"
  fi
}
valid_port() {
  local value="${1:-}"
  [[ "$value" =~ ^[0-9]{1,5}$ ]] && (( 10#$value >= 1 && 10#$value <= 65535 ))
}
# Comma-separated list of IPv4 addresses/CIDRs, e.g. RU-1,RU-2.
# Does not accept whitespace or empty elements.
valid_ipv4_sources() {
  local value="${1:-}" item
  local -a ips
  [[ -n "$value" && "$value" != ,* && "$value" != *, && "$value" != *,,* ]] || return 1
  IFS=, read -r -a ips <<< "$value"
  (( ${#ips[@]} > 0 )) || return 1
  for item in "${ips[@]}"; do
    valid_ip_or_cidr "$item" || return 1
  done
}
