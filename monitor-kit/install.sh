#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }

usage() {
 cat <<EOF
Usage:
  sudo ./install.sh panel
  sudo ./install.sh ru
  sudo ./install.sh foreign
  sudo ./install.sh register    # on panel, after node install
  sudo ./install.sh status

This kit installs only on clean hosts and does NOT migrate an existing K-VPN Monitor.
EOF
}
ask() { local prompt="$1" var="$2"; read -rp "$prompt" "$var" < /dev/tty; }
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
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

assert_clean() {
 local role="$1"
 if [[ -e /etc/kvpn-monitor || -e /opt/kvpn-monitor || -e /var/lib/kvpn-monitor ]]; then
   echo 'ERROR: K-VPN Monitor kit already installed; aborting to avoid overwrite.' >&2; exit 1
 fi
 if [[ "$role" == panel ]]; then
   if [[ -e /root/kvpn-monitor/check.py || -e /etc/systemd/system/kvpn-monitor.timer || -e /usr/local/libexec/kvpn-probe-receive ]]; then
     echo 'ERROR: existing panel monitor detected. This kit does not overwrite/migrate it.' >&2; exit 1
   fi
 else
   if [[ -e /etc/systemd/system/kvpn-probe.timer || -e /usr/local/sbin/kvpn-probe-send.sh ]]; then
     echo 'ERROR: existing RU probe detected. This kit does not overwrite/migrate it.' >&2; exit 1
   fi
 fi
}

install_panel() {
 assert_clean panel
 echo 'Installing PANEL role. Does not modify Remnawave/Docker/sshd configuration.'
 local chat thread token
 ask 'Telegram group chat_id (e.g. -100...): ' chat
 ask 'Telegram topic message_thread_id: ' thread
 [[ "$chat" =~ ^-?[0-9]+$ && "$thread" =~ ^[0-9]+$ ]] || { echo 'Invalid Telegram identifiers'; exit 1; }
 read -rsp 'Paste NEW bot token (hidden): ' token < /dev/tty; echo
 [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || { echo 'Invalid token format'; exit 1; }
 install -d -m 700 /etc/kvpn-monitor
 printf '%s\n' "$token" > /etc/kvpn-monitor/token
 chmod 600 /etc/kvpn-monitor/token
 unset token
 install -d -m 755 /opt/kvpn-monitor
 install -m 755 lib/monitor.py /opt/kvpn-monitor/monitor.py
 install -m 755 lib/receiver.py /opt/kvpn-monitor/receiver.py
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
 local pid panel port target type expected host_fingerprint
 ask 'Unique probe ID (e.g. ru-to-nl or nl-02-local): ' pid
 valid_id "$pid" || { echo 'Invalid probe ID'; exit 1; }
 ask 'Panel IP/hostname: ' panel
 [[ "$panel" =~ ^[a-zA-Z0-9.:-]+$ ]] || { echo 'Invalid host'; exit 1; }
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
 local target_port
 ask 'TCP port to probe [8443]: ' target_port
 target_port="${target_port:-8443}"
 valid_port "$target_port" || { echo 'Invalid target port'; exit 1; }
 echo 'IMPORTANT: on PANEL run: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'
 ask 'Paste trusted panel SSH ED25519 SHA256 fingerprint: ' expected
 [[ "$expected" =~ ^SHA256:[A-Za-z0-9+/=]+$ ]] || { echo 'Expected SHA256 fingerprint'; exit 1; }
 local tmp keyfound actual
 tmp=$(mktemp)
 trap 'rm -f "${tmp:-}"' EXIT
 ssh-keyscan -T 8 -p "$port" -t ed25519 "$panel" 2>/dev/null > "$tmp" || true
 [[ -s "$tmp" ]] || { echo 'Could not fetch panel SSH Ed25519 host key'; exit 1; }
 actual=$(ssh-keygen -lf "$tmp" | awk '{print $2}' | head -1)
 [[ "$actual" == "$expected" ]] || { echo 'Panel SSH host fingerprint mismatch; refusing to install' >&2; exit 1; }
 install -d -m 700 /etc/kvpn-monitor
 install -m 600 "$tmp" /etc/kvpn-monitor/known_hosts
 install -d -m 755 /opt/kvpn-monitor
 install -m 700 lib/sender.sh /opt/kvpn-monitor/sender.sh
 ssh-keygen -q -t ed25519 -f /etc/kvpn-monitor/monitor_key -N '' -C "kvpn-monitor-$pid"
 chmod 600 /etc/kvpn-monitor/monitor_key
 chmod 644 /etc/kvpn-monitor/monitor_key.pub
 # Environment file: all values validated, write as shell-escaped strings.
 {
   printf 'PROBE_ID=%q\n' "$pid"
   printf 'PANEL_HOST=%q\n' "$panel"
   printf 'PANEL_PORT=%q\n' "$port"
   printf 'CHECK_TYPE=%q\n' "$type"
   printf 'TARGET_HOST=%q\n' "$target"
   printf 'TARGET_PORT=%q\n' "$target_port"
 } > /etc/kvpn-monitor/probe.env
 chmod 600 /etc/kvpn-monitor/probe.env
 cat > /etc/systemd/system/kvpn-monitor-kit-probe.service <<'EOF'
[Unit]
Description=K-VPN Monitor Kit - send probe status
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/opt/kvpn-monitor/sender.sh
TimeoutStartSec=35
NoNewPrivileges=yes
EOF
 cat > /etc/systemd/system/kvpn-monitor-kit-probe.timer <<'EOF'
[Unit]
Description=K-VPN Monitor Kit - probe every 5 minutes
[Timer]
OnBootSec=1min
OnUnitInactiveSec=5min
AccuracySec=10s
Unit=kvpn-monitor-kit-probe.service
[Install]
WantedBy=timers.target
EOF
 systemctl daemon-reload
 echo
 echo 'NODE INSTALLED, TIMER NOT STARTED YET.'
 echo 'On panel, use ./install.sh register and paste the following PUBLIC key:'
 cat /etc/kvpn-monitor/monitor_key.pub
 echo "Probe ID: $pid"
 echo "Node source public IP: (determine on the node, e.g. curl -4 --noproxy '*' https://api.ipify.org)"
 echo 'After registering on panel, on this node run:'
 echo '  systemctl enable --now kvpn-monitor-kit-probe.timer'
 echo '  systemctl start kvpn-monitor-kit-probe.service'
}

register() {
 [[ -f /etc/kvpn-monitor/config.json && -f /opt/kvpn-monitor/receiver.py ]] || { echo 'Panel kit is not installed'; exit 1; }
 local pid label pub source stale fail recovery
 ask 'Probe ID (must match node): ' pid
 valid_id "$pid" || { echo 'Invalid ID'; exit 1; }
 ask 'Readable name (e.g. RU -> NL TCP): ' label
 [[ -n "$label" && ${#label} -le 100 ]] || { echo 'Invalid label'; exit 1; }
 ask 'Paste node PUBLIC ssh-ed25519 key (one line): ' pub
 [[ "$pub" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo 'Invalid Ed25519 public key'; exit 1; }
 ask 'Source IP of this node (required for SSH key restriction): ' source
 valid_ip "$source" || { echo 'Invalid IP'; exit 1; }
 ask 'Stale threshold seconds [720]: ' stale; stale="${stale:-720}"
 ask 'Consecutive failures [2]: ' fail; fail="${fail:-2}"
 ask 'Successes to recover [1]: ' recovery; recovery="${recovery:-1}"
 for n in "$stale" "$fail" "$recovery"; do [[ "$n" =~ ^[0-9]+$ ]] && (( 10#$n > 0 )) || { echo 'Invalid threshold'; exit 1; }; done
 python3 - "$pid" "$label" "$stale" "$fail" "$recovery" <<'PY'
import json,sys
from pathlib import Path
p=Path('/etc/kvpn-monitor/config.json')
d=json.loads(p.read_text())
pid,label,stale,fail,recovery=sys.argv[1:]
if any(x['id']==pid for x in d['probes']):
    raise SystemExit('ERROR: probe ID already registered. No changes made.')
d['probes'].append({'id':pid,'name':label,'stale_after':int(stale),'fail_threshold':int(fail),'recovery_threshold':int(recovery)})
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
PY
 local line
 line="from=\"$source\",restrict,command=\"/usr/bin/python3 /opt/kvpn-monitor/receiver.py $pid\" $pub"
 printf '%s\n' "$line" >> /home/kvpn-probe/.ssh/authorized_keys
 chown kvpn-probe:kvpn-probe /home/kvpn-probe/.ssh/authorized_keys
 chmod 600 /home/kvpn-probe/.ssh/authorized_keys
 echo "Registered $pid. Now enable and start the timer on the NODE."
}

case "${1:-}" in
 panel) install_panel;;
 ru) install_node ru;;
 foreign) install_node foreign;;
 register) register;;
 status) systemctl list-timers 'kvpn-monitor-kit*' --all --no-pager; [[ -f /etc/kvpn-monitor/config.json ]] && python3 -m json.tool /etc/kvpn-monitor/config.json || :;;
 *) usage; exit 1;;
esac
