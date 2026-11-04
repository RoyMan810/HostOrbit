#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source "../lib/tui.sh"
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd required' >&2; exit 1; }

ensure_monitor_dependencies() {
 local cmd missing=()
 for cmd in python3 ssh ssh-keygen ssh-keyscan timeout useradd passwd; do
   command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
 done
 if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
   missing+=(ca-certificates)
 fi
 if (( ${#missing[@]} > 0 )); then
   echo "Missing monitoring utilities: ${missing[*]}"
   command -v apt-get >/dev/null 2>&1 || { echo 'apt-get required to install dependencies' >&2; exit 1; }
   apt-get update -qq
   DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
     python3 openssh-client passwd coreutils ca-certificates
 fi
 for cmd in python3 ssh ssh-keygen ssh-keyscan timeout useradd passwd; do
   command -v "$cmd" >/dev/null 2>&1 || { echo "Required utility unavailable: $cmd" >&2; exit 1; }
 done
}

usage() {
 cat <<EOF
Usage:
  sudo ./install.sh panel
  sudo ./install.sh ru
  sudo ./install.sh foreign
  sudo ./install.sh register    # on panel, after node install
  sudo ./install.sh status
  sudo ./install.sh public-keys   # display agent PUBLIC keys only
  sudo ./install.sh test-telegram  # panel only: explicit test message

Existing monitoring is never overwritten automatically.
EOF
}
ask() {
  local prompt="$1" var="$2" answer
  if kvpn_ui_ready; then
    prompt=$(kvpn_ui_prompt_ru "$prompt")
    answer=$(kvpn_ui_input "$prompt" '') || { echo 'Отменено пользователем' >&2; exit 1; }
    printf -v "$var" '%s' "$answer"
  else
    read -rp "$prompt" "$var" < /dev/tty
  fi
}
valid_id() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,39}$ ]]; }
valid_ip() {
  python3 - "$1" <<'PYIP'
import ipaddress,sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PYIP
}
valid_port() { [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

assert_clean() {
 local role="$1"
 if [[ "$role" == panel ]]; then
   if [[ -e /etc/kvpn-monitor || -e /opt/kvpn-monitor || -e /var/lib/kvpn-monitor ||          -e /root/kvpn-monitor || -e /etc/systemd/system/kvpn-monitor.timer ||          -e /usr/local/libexec/kvpn-probe-receive ]]; then
     echo 'ERROR: existing panel monitor detected. This kit does not overwrite/migrate it.' >&2; exit 1
   fi
   if [[ -f /home/kvpn-probe/.ssh/authorized_keys ]] &&
      grep -Fq '/usr/local/libexec/kvpn-probe-receive' /home/kvpn-probe/.ssh/authorized_keys; then
     echo 'ERROR: an incompatible SSH probe key is already present. Refusing to overwrite it.' >&2; exit 1
   fi
 else
   if [[ -e /etc/systemd/system/kvpn-probe.timer || -e /usr/local/sbin/kvpn-probe-send.sh ||          -e /etc/kvpn-monitor/probe.env || -e /etc/systemd/system/kvpn-monitor-kit-probe.timer ||          -e /etc/kvpn-monitor/config.json ]]; then
     echo 'ERROR: old or panel monitor detected. This kit does not overwrite/migrate it.' >&2; exit 1
   fi
   if [[ -e /etc/kvpn-monitor && ! -d /etc/kvpn-monitor/probes ]]; then
     echo 'ERROR: unrecognized monitor configuration; refusing to modify.' >&2; exit 1
   fi
 fi
}

install_panel() {
 assert_clean panel
 ensure_monitor_dependencies
 echo 'Installing PANEL role. Does not modify Remnawave/Docker/sshd configuration.'
 local chat thread token
 ask 'Telegram group chat_id (e.g. -100...): ' chat
 ask 'Telegram topic message_thread_id: ' thread
 [[ "$chat" =~ ^-?[0-9]+$ && "$thread" =~ ^[0-9]+$ ]] || { echo 'Invalid Telegram identifiers'; exit 1; }
 token=$(kvpn_ui_password 'Введите токен Telegram-бота (скрыто)') || { echo 'Отменено' >&2; exit 1; }
 [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || { echo 'Invalid token format'; exit 1; }
 [[ -s /etc/ssh/ssh_host_ed25519_key.pub ]] || {
   echo 'Panel SSH Ed25519 host key missing. Configure sshd host key before installing monitoring.' >&2
   exit 1
 }
 install -d -m 700 /etc/kvpn-monitor
 printf '%s\n' "$token" > /etc/kvpn-monitor/token
 chmod 600 /etc/kvpn-monitor/token
 unset token
 install -d -m 755 /opt/kvpn-monitor
 install -m 755 lib/monitor.py /opt/kvpn-monitor/monitor.py
 install -m 755 lib/receiver.py /opt/kvpn-monitor/receiver.py
 install -m 700 lib/register.py /opt/kvpn-monitor/register.py
 if ! id kvpn-probe >/dev/null 2>&1; then
   useradd -m -s /bin/sh kvpn-probe
 fi
 passwd -l kvpn-probe >/dev/null || true
 install -d -m 700 -o kvpn-probe -g kvpn-probe /home/kvpn-probe/.ssh
 touch /home/kvpn-probe/.ssh/authorized_keys
 chown kvpn-probe:kvpn-probe /home/kvpn-probe/.ssh/authorized_keys
 chmod 600 /home/kvpn-probe/.ssh/authorized_keys
 install -d -m 711 /var/lib/kvpn-monitor
 install -d -m 700 -o kvpn-probe -g kvpn-probe /var/lib/kvpn-monitor/reports
 python3 - "$chat" "$thread" <<'PY'
import json,sys
from pathlib import Path
config={'chat_id':sys.argv[1], 'thread_id':int(sys.argv[2]), 'token_file':'/etc/kvpn-monitor/token', 'state_dir':'/var/lib/kvpn-monitor','probes':[]}
p=Path('/etc/kvpn-monitor/config.json');p.write_text(json.dumps(config,indent=2)+'\n');p.chmod(0o600)
PY
 cat > /etc/systemd/system/kvpn-monitor-kit.service <<'EOF'
[Unit]
Description=K-VPN Monitor Kit - status evaluation and Telegram notifications
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/kvpn-monitor/monitor.py
TimeoutStartSec=35
NoNewPrivileges=yes
EOF
 cat > /etc/systemd/system/kvpn-monitor-kit.timer <<'EOF'
[Unit]
Description=K-VPN Monitor Kit - evaluate status every minute
[Timer]
OnBootSec=1min
OnUnitInactiveSec=1min
AccuracySec=10s
Unit=kvpn-monitor-kit.service
[Install]
WantedBy=timers.target
EOF
 systemctl daemon-reload
 systemctl enable --now kvpn-monitor-kit.timer
 echo 'Panel installed. Register probes using: sudo ./install.sh register'
 echo 'SSH Ed25519 fingerprint for verifying on nodes:'
 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
}

install_node() {
 local role="$1"
 assert_clean node
 ensure_monitor_dependencies
 local pid panel port target type expected tmp actual target_port
 ask 'Unique probe ID (e.g. ru1-nl1, ru1-nl2 or nl1-local): ' pid
 valid_id "$pid" || { echo 'Invalid probe ID'; exit 1; }
 [[ ! -e "/etc/kvpn-monitor/probes/$pid.env" ]] || { echo 'Probe ID already exists; refusing overwrite' >&2; exit 1; }
 ask 'Monitoring panel IP/hostname: ' panel
 [[ "$panel" =~ ^[a-zA-Z0-9.:-]+$ ]] || { echo 'Invalid panel host'; exit 1; }
 ask 'Panel SSH port [22]: ' port
 port="${port:-22}"
 valid_port "$port" || { echo 'Invalid SSH port'; exit 1; }
 if [[ "$role" == ru ]]; then
   type=remote_tcp
   ask 'Foreign node IP/hostname to probe: ' target
   [[ "$target" =~ ^[a-zA-Z0-9.:-]+$ ]] || { echo 'Invalid probe host'; exit 1; }
 else
   type=local_tcp
   target=127.0.0.1
 fi
 ask 'TCP port to probe [8443]: ' target_port
 target_port="${target_port:-8443}"
 valid_port "$target_port" || { echo 'Invalid target port'; exit 1; }
 echo 'On the panel check: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'
 ask 'Paste verified monitoring panel ED25519 SHA256 fingerprint: ' expected
 [[ "$expected" =~ ^SHA256:[A-Za-z0-9+/=]+$ ]] || { echo 'Expected SHA256 fingerprint'; exit 1; }
 tmp=$(mktemp)
 trap 'rm -f "${tmp:-}"' EXIT
 # SSH key exchange can be transiently slow even when TCP/22 is reachable.
 # Retry ONLY retrieval; never accept an unchecked or mismatched host key.
 local attempt
 for attempt in 1 2 3; do
   ssh-keyscan -T 10 -p "$port" -t ed25519 "$panel" 2>/dev/null > "$tmp" || true
   [[ -s "$tmp" ]] && break
   if (( attempt < 3 )); then sleep 2; fi
 done
 [[ -s "$tmp" ]] || {
   echo 'Could not fetch panel SSH Ed25519 key after 3 attempts.' >&2
   echo "Check TCP access and run: ssh-keyscan -T 10 -p $port -t ed25519 $panel" >&2
   exit 1
 }
 actual=$(ssh-keygen -lf "$tmp" | awk '{print $2}' | head -1)
 [[ "$actual" == "$expected" ]] || { echo 'Panel fingerprint mismatch; refusing to install' >&2; exit 1; }
 install -d -m 700 /etc/kvpn-monitor /etc/kvpn-monitor/probes
 install -d -m 755 /opt/kvpn-monitor
 install -m 700 lib/sender.sh /opt/kvpn-monitor/sender.sh
 install -m 600 "$tmp" "/etc/kvpn-monitor/probes/$pid.known_hosts"
 ssh-keygen -q -t ed25519 -f "/etc/kvpn-monitor/probes/$pid.key" -N '' -C "kvpn-monitor-$pid"
 chmod 600 "/etc/kvpn-monitor/probes/$pid.key"
 chmod 644 "/etc/kvpn-monitor/probes/$pid.key.pub"
 {
   printf 'PROBE_ID=%q\n' "$pid"
   printf 'PANEL_HOST=%q\n' "$panel"
   printf 'PANEL_PORT=%q\n' "$port"
   printf 'CHECK_TYPE=%q\n' "$type"
   printf 'TARGET_HOST=%q\n' "$target"
   printf 'TARGET_PORT=%q\n' "$target_port"
 } > "/etc/kvpn-monitor/probes/$pid.env"
 chmod 600 "/etc/kvpn-monitor/probes/$pid.env"
 if [[ ! -e /etc/systemd/system/kvpn-monitor-kit-probe@.service ]]; then
   cat > /etc/systemd/system/kvpn-monitor-kit-probe@.service <<'EOF'
[Unit]
Description=K-VPN Monitor Kit probe %i
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/opt/kvpn-monitor/sender.sh %i
TimeoutStartSec=35
NoNewPrivileges=yes
EOF
 fi
 if [[ ! -e /etc/systemd/system/kvpn-monitor-kit-probe@.timer ]]; then
   cat > /etc/systemd/system/kvpn-monitor-kit-probe@.timer <<'EOF'
[Unit]
Description=K-VPN Monitor Kit probe timer %i
[Timer]
OnBootSec=1min
OnUnitInactiveSec=5min
AccuracySec=10s
Unit=kvpn-monitor-kit-probe@%i.service
[Install]
WantedBy=timers.target
EOF
 fi
 systemctl daemon-reload
 echo
 echo 'MONITOR PROBE CONFIGURED. Timer is NOT started yet.'
 echo 'On monitoring panel register this probe ID and PUBLIC key:'
 cat "/etc/kvpn-monitor/probes/$pid.key.pub"
 echo "Probe ID: $pid"
 echo 'Ensure the public source IPv4 used by this node is registered on the panel.'
 echo 'After registering the key on monitoring panel, start on this node:'
 echo "  systemctl enable --now 'kvpn-monitor-kit-probe@$pid.timer'"
 echo "  systemctl start 'kvpn-monitor-kit-probe@$pid.service'"
 echo 'Repeat monitor ru / monitor foreign with another unique ID to add another target.'
 rm -f "$tmp"; trap - EXIT
}

register() {
 [[ -f /etc/kvpn-monitor/config.json && -f /opt/kvpn-monitor/receiver.py ]] || { echo 'Panel kit is not installed'; exit 1; }
 ensure_monitor_dependencies
 local pid label pub source stale fail recovery
 ask 'Probe ID (must match node): ' pid
 valid_id "$pid" || { echo 'Invalid ID'; exit 1; }
 ask 'Readable name (e.g. RU -> NL TCP): ' label
 [[ -n "$label" && ${#label} -le 100 ]] || { echo 'Invalid label'; exit 1; }
 ask 'Paste node PUBLIC ssh-ed25519 key (one line): ' pub
 [[ "$pub" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo 'Invalid Ed25519 public key'; exit 1; }
 local keytest
 keytest=$(mktemp)
 printf '%s\n' "$pub" > "$keytest"
 if ! ssh-keygen -lf "$keytest" -E sha256 >/dev/null 2>&1; then
   rm -f "$keytest"
   echo 'SSH key is malformed' >&2; exit 1
 fi
 rm -f "$keytest"
 ask 'Source IP of this node (required for SSH key restriction): ' source
 valid_ip "$source" || { echo 'Invalid IP'; exit 1; }
 ask 'Stale threshold seconds [720]: ' stale; stale="${stale:-720}"
 ask 'Consecutive failures [2]: ' fail; fail="${fail:-2}"
 ask 'Successes to recover [1]: ' recovery; recovery="${recovery:-1}"
 for n in "$stale" "$fail" "$recovery"; do [[ "$n" =~ ^[0-9]+$ ]] && (( 10#$n > 0 )) || { echo 'Invalid threshold'; exit 1; }; done
 # Registration is recoverable after an interrupted write and rejects key collisions.
 python3 /opt/kvpn-monitor/register.py "$pid" "$label" "$pub" "$source" "$stale" "$fail" "$recovery"
 echo "Registered $pid. Now enable and start the timer on the NODE."
}

show_public_keys() {
 local directory=/etc/kvpn-monitor/probes key found=0
 [[ -d "$directory" ]] || { echo 'No agent probe directory on this host.'; return 0; }
 for key in "$directory"/*.key.pub; do
   [[ -f "$key" ]] || continue
   found=1
   printf '\n--- %s ---\n' "${key##*/}"
   cat -- "$key"
 done
 (( found == 1 )) || echo 'No public keys found.'
}

monitor_status() {
 echo '=== K-VPN Monitor timers ==='
 systemctl list-timers 'kvpn-monitor-kit*' --all --no-pager || true
 if [[ -f /etc/kvpn-monitor/config.json ]]; then
   echo '=== Monitoring panel: registered probes and last state ==='
   python3 - <<'PY'
import json
from pathlib import Path
config = json.loads(Path('/etc/kvpn-monitor/config.json').read_text())
try:
    states = json.loads(Path('/var/lib/kvpn-monitor/state.json').read_text())
except (FileNotFoundError, ValueError):
    states = {}
for probe in config.get('probes', []):
    entry = states.get(probe['id'], {})
    print(f"{probe['id']}: {entry.get('state', 'INIT')} | "
          f"last_timestamp={entry.get('last_timestamp', 'none')} | "
          f"{probe.get('name', '')}")
if not config.get('probes'):
    print('No probes registered yet.')
PY
 elif [[ -d /etc/kvpn-monitor/probes ]]; then
   echo '=== Agent probe instances ==='
   local envfile id
   for envfile in /etc/kvpn-monitor/probes/*.env; do
     [[ -f "$envfile" ]] || continue
     id="${envfile##*/}"; id="${id%.env}"
     printf '%s: timer=' "$id"
     systemctl is-active "kvpn-monitor-kit-probe@$id.timer" || true
   done
 else
   echo 'Monitor kit is not configured on this host.'
 fi
}

case "${1:-}" in
 panel) install_panel;;
 ru) install_node ru;;
 foreign) install_node foreign;;
 register) register;;
 test-telegram) [[ -s /etc/kvpn-monitor/config.json ]] || { echo 'Panel kit is not installed'; exit 1; }; python3 /opt/kvpn-monitor/monitor.py --test-telegram;;
 status) monitor_status;;
 public-keys) show_public_keys;;
 *) usage; exit 1;;
esac
