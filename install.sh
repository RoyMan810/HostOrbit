#!/usr/bin/env bash
# K-VPN Node Deployer — safe installation on FRESH Ubuntu/Debian VPS.
set -Eeuo pipefail
umask 077
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/etc/kvpn-node-deployer
NODE_DIR=/opt/remnanode
source "$ROOT_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
K-VPN Node Deployer — new server only

  sudo ./install.sh                     interactive menu (choose individual tasks)
  sudo ./install.sh menu                same interactive menu
  sudo ./install.sh node                install ONLY Remnawave Node (requires prepared UFW)
  sudo ./install.sh firewall            configure ONLY UFW rules (new VPS)
  sudo ./install.sh firewall-add-ru     add RU source to an installed foreign node
  sudo ./install.sh docker              install ONLY Docker + Compose
  sudo ./install.sh wizard              full guided installation (new VPS)
  sudo ./install.sh preflight           read-only environment checks
  sudo ./install.sh decoy               optional local HTTPS REALITY target (9444)
  sudo ./install.sh backup              backup service on a prepared node
  sudo ./install.sh monitor panel       monitoring hub on a NEW panel server
  sudo ./install.sh monitor ru          monitoring agent on a NEW RU node
  sudo ./install.sh monitor foreign     monitoring agent on a NEW foreign node
  sudo ./install.sh monitor register    register agent on NEW monitoring panel
  sudo ./install.sh status              read-only health summary
  sudo ./install.sh diagnostics         write redacted diagnostic text file
  sudo ./install.sh help

Does NOT install Remnawave Panel. VPN configurations, REALITY keys,
Xray inbounds/outbounds and subscriptions are managed in Remnawave Panel.
EOF
}

supported_distribution() {
  # Interim Ubuntu releases 24.10/25.x are EOL in November 2026.
  # These are the currently supported Ubuntu LTS/interim releases in Docker docs.
  case "$1:$2" in
    ubuntu:24.04|ubuntu:26.04|ubuntu:26.10|debian:12|debian:13) return 0;;
    *) return 1;;
  esac
}
require_debian() {
  [[ -f /etc/os-release ]] || die 'Only supported Ubuntu/Debian versions are allowed'
  . /etc/os-release
  supported_distribution "${ID:-}" "${VERSION_ID:-}" || \
    die "Unsupported or EOL OS: ${ID:-unknown} ${VERSION_ID:-unknown}. Use Ubuntu 24.04/26.04/26.10 or Debian 12/13."
  command -v systemctl >/dev/null || die 'systemd is required'
  command -v apt-get >/dev/null || die 'apt-get is required'
}

preflight() {
  require_debian
  . /etc/os-release
  echo "OS: $PRETTY_NAME"
  echo "Architecture: $(uname -m)"
  echo "RAM: $(awk '/MemTotal/ { printf "%.0f MiB", $2/1024 }' /proc/meminfo)"
  echo "Swap: $(awk '/SwapTotal/ { printf "%.0f MiB", $2/1024 }' /proc/meminfo)"
  echo "Disk available on /: $(df -hP / | awk 'NR==2 {print $4}')"
  if command -v docker >/dev/null; then
    docker --version || true
    docker compose version 2>/dev/null || true
  else
    echo 'Docker: not installed'
  fi
  if command -v ufw >/dev/null; then
    ufw status | head -8 || true
  else
    echo 'UFW: not installed'
  fi
  echo 'Port listeners (22, 80, 443, 2222, 8443, 9444, 10000):'
  if command -v ss >/dev/null; then
    ss -H -lnt 2>/dev/null | awk '$4 ~ /:(22|80|443|2222|8443|9444|10000)$/ {print $4}' | sort -u
  fi
  if [[ -e "$NODE_DIR" ]]; then
    echo "EXISTING NODE DIRECTORY: $NODE_DIR (wizard will refuse installation)"
  fi
  if [[ -e /etc/systemd/system/kvpn-probe.timer || -e /root/kvpn-monitor/check.py ]]; then
    echo 'EXISTING LEGACY MONITOR DETECTED: do not install monitor kit over it.'
  fi
  echo 'Utilities (missing ones can be installed before provisioning; nano is optional):'
  local util
  for util in python3 curl nano tar gzip base64 ssh-keygen ssh-keyscan timeout ss; do
    if command -v "$util" >/dev/null 2>&1; then
      printf '  %-13s OK\n' "$util"
    else
      printf '  %-13s MISSING\n' "$util"
    fi
  done
  echo 'Preflight is read-only.'
}

optional_swap() {
  local ram_kb swap_kb disk_kb
  ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
  if (( ram_kb >= 1048576 || swap_kb > 0 )); then return; fi
  warn 'This VPS has less than 1 GiB RAM and no swap; official Node requirement is >= 1 GiB RAM.'
  disk_kb=$(df -Pk / | awk 'NR==2 {print $4}')
  if (( disk_kb < 2097152 )); then warn 'Not enough free disk to add 1 GiB swap safely.'; return; fi
  if confirm 'Create a 1 GiB swapfile to reduce memory pressure? (does not replace RAM)'; then
    [[ ! -e /swapfile ]] || die 'Existing /swapfile detected; refusing to overwrite'
    fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=progress
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -Eq '^[^#]*[[:space:]]/swapfile[[:space:]]' /etc/fstab || \
      printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
    echo '1 GiB swap enabled.'
  fi
}

install_packages() {
  local packages=("$@")
  (( ${#packages[@]} > 0 )) || return 0
  printf 'Installing packages: %s\n' "${packages[*]}"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    docker compose version >/dev/null 2>&1 || \
      die 'Docker exists without Compose plugin. Fix manually; will not replace existing Docker packages.'
    echo 'Docker + Compose already present.'
  else
    echo 'Docker Engine will be installed via the official Docker APT repository.'
    confirm 'Configure Docker APT repository and install Docker Engine + Compose?' || die 'Docker installation declined'
    install_packages ca-certificates curl
    . /etc/os-release
    local distro="$ID" codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}" arch key_tmp
    [[ "$codename" =~ ^[a-z0-9]+$ ]] || die 'Invalid or missing OS codename'
    arch=$(dpkg --print-architecture)
    [[ "$arch" =~ ^[a-z0-9]+$ ]] || die 'Invalid CPU architecture'
    [[ ! -e /etc/apt/sources.list.d/docker.sources ]] || \
      die 'Docker APT repository already configured. Inspect existing Docker setup manually.'
    [[ ! -e /etc/apt/keyrings/docker.asc ]] || \
      die 'Docker signing key already exists. Inspect existing Docker setup manually.'
    install -d -m 755 /etc/apt/keyrings
    key_tmp=$(mktemp /etc/apt/keyrings/.docker.asc.XXXXXX)
    if ! curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 \
      "https://download.docker.com/linux/$distro/gpg" -o "$key_tmp"; then
      rm -f -- "$key_tmp"
      die 'Failed to download Docker repository signing key'
    fi
    [[ -s "$key_tmp" ]] || { rm -f -- "$key_tmp"; die 'Docker signing key is empty'; }
    chmod 644 "$key_tmp"
    mv -- "$key_tmp" /etc/apt/keyrings/docker.asc
    cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$distro
Suites: $codename
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    apt-get update -qq || die 'Docker repository unavailable for this OS/architecture'
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  systemctl enable --now docker
  docker compose version >/dev/null || die 'Docker Compose plugin not found'
}

port_unused() {
  local port="$1"
  command -v ss >/dev/null 2>&1 || die 'ss is required for port checks (install iproute2)'
  ! ss -H -lnt | awk '{print $4}' | grep -Eq ":${port}$"
}

setup_firewall() {
  local panel_ip="$1" nodeport="$2" vpnport="$3" vpn_source="$4" sshport="$5" allow_http="$6"
  install_packages ufw iproute2
  echo
  echo 'Planned UFW rules:'
  echo " - SSH port $sshport/tcp: kept as-is if UFW active; opened publicly only when enabling fresh UFW"
  echo " - Node API $nodeport/tcp only from $panel_ip"
  echo " - VPN transport $vpnport/tcp only from $vpn_source"
  [[ "$allow_http" == yes ]] && echo ' - HTTP 80/tcp from any IP (ACME certificate issuance/renewal)'
  echo 'Existing UFW rules are preserved; no rules are deleted.'
  local ufw_active=no
  if ufw status | grep -qi '^Status: active'; then ufw_active=yes; fi
  if [[ "$ufw_active" == yes ]] && ufw status verbose | grep -Eq '^Default: allow \(incoming\)'; then
    die 'UFW is active with default ALLOW incoming. Change firewall policy manually before provisioning.'
  fi
  # Refuse an existing allow-all rule even if a separate specific Node API rule exists.
  if [[ "$ufw_active" == yes ]] && ufw status | grep -Eq '^Anywhere( \(v6\))?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+Anywhere'; then
    die 'UFW has a global ALLOW Anywhere rule; Node API would be exposed.'
  fi
  # Refuse to install on top of a preexisting globally exposed Node API.
  if [[ "$ufw_active" == yes ]] && ufw status | grep -Eq "^${nodeport}(/tcp)?( \(v6\))?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+Anywhere"; then
    die 'Node API port already allowed from Anywhere in UFW (IPv4 or IPv6); fix manually first.'
  fi
  if [[ "$ufw_active" == no ]]; then
    echo 'UFW is currently inactive. Enabling it changes the host firewall.'
    confirm 'Apply rules and ENABLE UFW?' || die 'UFW needs to be active before starting a public Node API'
  else
    confirm 'Apply the listed additional UFW rules?' || die 'Firewall rules not approved'
  fi
  # Do not enable an inactive firewall with a mistyped SSH port.
  if [[ "$ufw_active" == no ]]; then
    port_unused "$sshport" && die "SSH port $sshport has no TCP listener; refusing to enable UFW"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      local remote_ip remote_port local_ip actual_ssh_port
      read -r remote_ip remote_port local_ip actual_ssh_port <<< "$SSH_CONNECTION"
      [[ "$actual_ssh_port" == "$sshport" ]] || \
        die "Entered SSH port $sshport differs from current SSH session port $actual_ssh_port"
    fi
  fi
  # Never widen an EXISTING SSH allowlist on an active host firewall.
  if [[ "$ufw_active" == no ]]; then
    ufw allow "$sshport/tcp" comment 'KVPN keep SSH' >/dev/null
  fi
  ufw allow from "$panel_ip" to any port "$nodeport" proto tcp comment 'KVPN panel only' >/dev/null
  local source
  local -a sources
  IFS=, read -r -a sources <<< "$vpn_source"
  for source in "${sources[@]}"; do
    if [[ "$source" == '0.0.0.0/0' ]]; then
      ufw allow "$vpnport/tcp" comment 'KVPN public inbound' >/dev/null
    else
      ufw allow from "$source" to any port "$vpnport" proto tcp comment 'KVPN approved transport source' >/dev/null
    fi
  done
  if [[ "$allow_http" == yes ]]; then
    ufw allow 80/tcp comment 'KVPN ACME HTTP-01 renewal' >/dev/null
  fi
  if [[ "$ufw_active" == no ]]; then
    ufw default deny incoming >/dev/null
    ufw --force enable >/dev/null
  fi
  ufw status numbered
}

# Node-only installation never adjusts UFW. Verify that the management API
# is already restricted locally before starting an Internet-facing container.
assert_node_api_protected() {
  local panel_ip="$1" nodeport="$2" rules
  command -v ufw >/dev/null 2>&1 || die 'Node-only: UFW is missing. Configure firewall first (menu: UFW).'
  ufw status verbose | grep -Eqi '^Status: active' || die 'Node-only: UFW is inactive. Configure UFW first.'
  ufw status verbose | grep -Eqi '^Default: deny \(incoming\)' || \
    die 'Node-only: UFW inbound policy must be deny.'
  rules=$(ufw status)
  if grep -Eq '^Anywhere( \(v6\))?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+Anywhere' <<< "$rules"; then
    die 'Node-only: an allow-all UFW rule exposes the API; fix it first.'
  fi
  if grep -Eq "^${nodeport}(/tcp)?( \(v6\))?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+Anywhere" <<< "$rules"; then
    die 'Node-only: Node API allows Anywhere; restrict it first.'
  fi
  grep -Eq "^${nodeport}(/tcp)?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+${panel_ip//./\.}([[:space:]]|$)" <<< "$rules" || \
    die "Node-only: no UFW ALLOW rule for panel $panel_ip -> TCP $nodeport. Configure UFW first."
  echo 'Verified active UFW default deny and restricted Node API allow rule.'
}

# Independent firewall configuration: no Docker, Node or monitoring changes.
configure_firewall_only() {
  require_debian
  [[ ! -e "$NODE_DIR" && ! -L "$NODE_DIR" ]] ||     die 'Existing node detected. Separate UFW setup is only for a NEW VPS; do not alter production rules.'
  preflight
  local panel_ip nodeport vpnport vpn_source sshport acme role
  echo 'This operation configures ONLY UFW. Existing node, Docker and monitoring are not installed.'
  confirm 'Proceed to collect UFW settings?' || die 'Cancelled'
  role=$(ask_default 'Role (ru / foreign)' 'foreign')
  [[ "$role" == ru || "$role" == foreign ]] || die 'Role must be ru or foreign'
  panel_ip=$(ask_default 'Remnawave Panel public IPv4' '')
  valid_ipv4 "$panel_ip" || die 'Invalid Panel IPv4'
  nodeport=$(ask_default 'Node API port from panel compose' '2222')
  valid_port "$nodeport" || die 'Invalid Node API port'
  if [[ "$role" == foreign ]]; then
    vpnport=$(ask_default 'Xray TCP inbound port' '8443')
    vpn_source=$(ask_default 'Allowed RU IPs/CIDRs (comma-separated, e.g. 2 RU nodes)' '')
  else
    vpnport=$(ask_default 'Public TCP inbound port' '443')
    vpn_source=$(ask_default 'Allowed client source' '0.0.0.0/0')
  fi
  valid_port "$vpnport" || die 'Invalid inbound port'
  valid_ipv4_sources "$vpn_source" || die 'Invalid source IPv4/CIDR list'
  [[ "$role" != foreign || ",$vpn_source," != *,0.0.0.0/0,* ]] || \
    die 'Foreign node must not expose transport to all IPv4 sources'
  sshport=$(ask_default 'Current SSH port' '22')
  valid_port "$sshport" || die 'Invalid SSH port'
  [[ "$nodeport" != "$vpnport" && "$nodeport" != "$sshport" && "$vpnport" != "$sshport" ]] || \
    die 'SSH, Node API and VPN transport ports must be distinct'
  [[ "$nodeport" != 80 && "$nodeport" != 443 && "$nodeport" != 9444 ]] || \
    die 'Node API must not use the public HTTP/HTTPS or decoy ports'
  acme=$(ask_default 'Allow public 80/tcp for ACME? (yes/no)' 'no')
  [[ "$acme" == yes || "$acme" == no ]] || die 'Answer yes or no'
  if [[ "$acme" == yes ]]; then
    [[ "$vpnport" != 80 && "$vpnport" != 9444 ]] || die 'ACME reserves ports 80 and 9444'
  fi
  setup_firewall "$panel_ip" "$nodeport" "$vpnport" "$vpn_source" "$sshport" "$acme"
  echo 'UFW configured. No Docker containers or node services were changed.'
}

# Expand allowed source IPs when a NEW Russian node is introduced.
# This is the only firewall action allowed on an existing installer-managed
# foreign node; it adds a single rule and never touches Docker or VPN profiles.
add_ru_firewall_source() {
  require_debian
  [[ -f "$STATE_DIR/node.env" ]] || die 'No installer-managed Node config. Configure manually.'
  source "$STATE_DIR/node.env"
  [[ "${ROLE:-}" == foreign ]] || die 'This action only applies to foreign nodes.'
  [[ -n "${VPN_PORT:-}" ]] && valid_port "$VPN_PORT" || die 'Invalid VPN port in saved settings'
  command -v ufw >/dev/null 2>&1 || die 'UFW not installed'
  ufw status | grep -qi '^Status: active' || die 'UFW is inactive; refusing rule change'
  local source_ip
  source_ip=$(ask_default 'New RU source IPv4/CIDR' '')
  valid_ip_or_cidr "$source_ip" || die 'Invalid RU IPv4/CIDR'
  local -a current_ips
  IFS=, read -r -a current_ips <<< "${VPN_SOURCE:-}"
  local existing
  for existing in "${current_ips[@]}"; do
    [[ "$existing" != "$source_ip" ]] || die 'This source is already configured'
  done
  if [[ "${VPN_SOURCE:-}" == '0.0.0.0/0' ]]; then
    die 'VPN port is already public; do not add specific RU rules to a public inbound'
  fi
  echo "Planned UFW addition: allow TCP $VPN_PORT from $source_ip"
  confirm 'Add ONLY this UFW rule?' || die 'Cancelled'
  ufw allow from "$source_ip" to any port "$VPN_PORT" proto tcp comment 'KVPN additional RU source'
  local tmp
  tmp=$(mktemp "$STATE_DIR/.node.env.XXXXXX")
  grep -v '^VPN_SOURCE=' "$STATE_DIR/node.env" > "$tmp"
  printf 'VPN_SOURCE=%q\n' "${VPN_SOURCE:+$VPN_SOURCE,}$source_ip" >> "$tmp"
  chmod 600 "$tmp"
  mv -- "$tmp" "$STATE_DIR/node.env"
  echo "Source added. Also update the relevant routing/configuration in Remnawave Panel."
}

validate_compose() {
  local compose_dir="$1" expected_port="$2"
  (cd "$compose_dir" && docker compose config -q)
  # Feed Compose JSON through stdin, never put secrets in argv, env, or /tmp files.
  local checker
  checker=$(cat <<'PYCODE'
import json,sys
c=json.load(sys.stdin)
services=c.get('services',{})
if len(services)!=1 or 'remnanode' not in services:
    raise SystemExit('ERROR: compose must contain only a service named remnanode')
s=services['remnanode']
if s.get('network_mode')!='host':
    raise SystemExit('ERROR: remnanode must use network_mode: host')
image=s.get('image','')
if not image.startswith('remnawave/node:'):
    raise SystemExit('ERROR: expected official remnawave/node image')
env=s.get('environment',{})
if isinstance(env,list):
    env=dict(x.split('=',1) for x in env if '=' in x)
port=env.get('NODE_PORT') or env.get('APP_PORT')
if port is None:
    raise SystemExit('ERROR: no NODE_PORT/APP_PORT in compose config')
if str(port)!=sys.argv[1]:
    raise SystemExit(f'ERROR: node API port mismatch: compose={port} firewall={sys.argv[1]}')
if not (env.get('SECRET_KEY') or env.get('SSL_CERT')):
    raise SystemExit('ERROR: compose has no SECRET_KEY/SSL_CERT; copy exact config from Remnawave Panel')
print(f'Compose validated: service=remnanode image={image} node_api_port={port}; secret present (hidden)')
PYCODE
)
  (cd "$compose_dir" && docker compose config --format json) | python3 -c "$checker" "$expected_port"
}

install_node() {
  local mode="${1:-full}"
  [[ "$mode" == full || "$mode" == node_only ]] || die 'Unknown node installation mode'
  require_debian
  [[ -e /etc/ssh/ssh_host_ed25519_key.pub ]] || warn 'No Ed25519 host key found; confirm SSH access.'
  [[ ! -e "$NODE_DIR" && ! -L "$NODE_DIR" ]] || \
    die 'Existing /opt/remnanode directory detected: refusing to install over existing files.'
  [[ ! -e "$STATE_DIR/node.env" ]] || die 'This node already managed by the installer; refusing duplicate installation.'
  if [[ "$mode" == full ]]; then
    echo 'Full wizard: Docker, Remnawave Node, UFW and optional components.'
  else
    echo 'Node-only: install Docker and Remnawave Node; DO NOT change UFW, nginx, backup or monitoring.'
    echo 'Before installation, configure UFW with the separate firewall menu item.'
  fi
  preflight
  local role panel_ip nodeport vpnport vpn_source sshport acme source_file
  role=$(ask_default 'Server role (ru / foreign)' 'foreign')
  [[ "$role" == ru || "$role" == foreign ]] || die 'Role must be ru or foreign'
  panel_ip=$(ask_default 'Remnawave Panel public IPv4 (required)' '')
  valid_ipv4 "$panel_ip" || die 'Invalid panel IP'
  nodeport=$(ask_default 'Node API port from the panel-generated compose' '2222')
  valid_port "$nodeport" || die 'Invalid node API port'
  if [[ "$role" == foreign ]]; then
    vpnport=$(ask_default 'Xray TCP inbound port (configured LATER in Panel)' '8443')
    vpn_source=$(ask_default 'RU IP addresses/CIDRs allowed for Xray (comma-separated)' '')
  else
    vpnport=$(ask_default 'Public TCP inbound port (configured LATER in Panel)' '443')
    vpn_source=$(ask_default 'Allowed client source (0.0.0.0/0 for public)' '0.0.0.0/0')
  fi
  valid_port "$vpnport" || die 'Invalid transport port'
  valid_ipv4_sources "$vpn_source" || die 'Invalid source IPv4/CIDR list'
  [[ "$role" != foreign || ",$vpn_source," != *,0.0.0.0/0,* ]] || \
    die 'Foreign node must not expose transport to all IPv4 sources'
  [[ "$vpnport" != "$nodeport" ]] || die 'Node API port must differ from VPN traffic port'
  [[ "$nodeport" != 80 && "$nodeport" != 443 && "$nodeport" != 9444 ]] || \
    die 'Do not use public HTTP/HTTPS/decoy ports for the private Node management API'
  sshport=$(ask_default 'Current inbound SSH port (verify this carefully!)' '22')
  valid_port "$sshport" || die 'Invalid SSH port'
  acme=$(ask_default 'Will you install an ACME HTTP-01 HTTPS decoy on this node later? (yes/no)' 'no')
  [[ "$acme" == yes || "$acme" == no ]] || die 'Answer yes or no'
  [[ "$nodeport" != "$sshport" ]] || die 'Node API port cannot equal SSH port'
  [[ "$vpnport" != "$sshport" ]] || die 'VPN port cannot equal SSH port'
  if [[ "$acme" == yes ]]; then
    [[ "$vpnport" != 80 && "$vpnport" != 9444 ]] || die 'ACME HTTP port 80 and local decoy port 9444 must be reserved'
  fi
  echo
  echo 'In Remnawave Panel: Nodes -> Management -> + -> Copy docker-compose.yml.'
  echo 'Save the EXACT file on this new host, e.g. /root/new-remnanode-compose.yml (mode 600).'
  echo 'Do not share its contents: it contains a secret.'
  source_file=$(ask_default 'Absolute path to Panel-generated docker-compose.yml' '/root/new-remnanode-compose.yml')
  [[ "$source_file" == /* && -f "$source_file" && ! -L "$source_file" ]] || die 'Compose path must be an existing absolute regular file (not symlink)'
  if [[ "$(stat -c '%a' "$source_file")" != 600 ]]; then
    warn 'Compose file includes a secret; making it root-readable only (chmod 600)'
    chmod 600 "$source_file"
  fi
  if [[ "$mode" == full ]]; then
    confirm 'Proceed with Docker installation and firewall changes on this NEW VPS?' || die 'Cancelled'
  else
    # Fail BEFORE installation/modifications if the required firewall guard is absent.
    assert_node_api_protected "$panel_ip" "$nodeport"
    confirm 'Install ONLY Remnawave Node and Docker (leave firewall untouched)?' || die 'Cancelled'
  fi
  # Minimal Ubuntu images may omit Python, curl, the editor or networking tools.
  # nano is optional and NOT a prerequisite: we never invoke an editor.
  install_packages python3 ca-certificates curl openssh-client iproute2 coreutils tar gzip util-linux libc-bin
  optional_swap
  install_docker
  port_unused "$nodeport" || die 'Node API port already has a listener; refusing to deploy.'
  # Compose validated in a temporary directory. No changes to the active node until validation succeeds.
  local staging
  staging=$(mktemp -d /root/.kvpn-node-staging.XXXXXX)
  trap '[[ -n "${staging:-}" ]] && rm -rf -- "$staging"' EXIT
  cp -- "$source_file" "$staging/docker-compose.yml"
  chmod 600 "$staging/docker-compose.yml"
  validate_compose "$staging" "$nodeport"
  if [[ "$mode" == full ]]; then
    setup_firewall "$panel_ip" "$nodeport" "$vpnport" "$vpn_source" "$sshport" "$acme"
  else
    # Recheck just before Docker starts; no firewall changes are made here.
    assert_node_api_protected "$panel_ip" "$nodeport"
  fi
  install -d -m 700 "$NODE_DIR" "$STATE_DIR"
  install -m 600 "$staging/docker-compose.yml" "$NODE_DIR/docker-compose.yml"
  printf 'ROLE=%q\nPANEL_IP=%q\nNODE_API_PORT=%q\nVPN_PORT=%q\nVPN_SOURCE=%q\nSSH_PORT=%q\n' \
    "$role" "$panel_ip" "$nodeport" "$vpnport" "$vpn_source" "$sshport" > "$STATE_DIR/node.env"
  chmod 600 "$STATE_DIR/node.env"
  echo 'Starting Remnawave Node container...'
  (cd "$NODE_DIR" && docker compose pull && docker compose up -d)
  (cd "$NODE_DIR" && docker compose ps)
  echo
  echo 'NEXT (in panel): finish creating node, choose correct Config Profile, configure Xray inbounds/outbounds.'
  echo "Node API: $nodeport TCP (restricted to $panel_ip by UFW)"
  echo "VPN TCP port: $vpnport (source $vpn_source)"
  echo 'Note: Node is not a working VPN endpoint until the Panel delivers a valid Xray configuration.'
  if [[ "$mode" == full ]]; then
    if confirm 'Install a daily root-only configuration backup now?'; then install_backup; fi
    if [[ "$acme" == yes ]]; then
      if confirm 'Configure local HTTPS REALITY decoy now? (requires working DNS and public port 80)'; then install_decoy; fi
    fi
    if confirm 'Also install the optional monitoring agent? (requires NEW monitor-kit hub, not legacy panel)'; then
      (cd "$ROOT_DIR/monitor-kit" && ./install.sh "$role")
    fi
  else
    echo 'Node-only complete. Firewall/backup/nginx/monitoring were not modified.'
  fi
  rm -rf "$staging"
  trap - EXIT
}

install_backup() {
  require_debian
  [[ -d "$NODE_DIR" ]] || die 'Node directory not found; provision node first'
  local script=/usr/local/sbin/kvpn-node-backup.sh
  if [[ -e "$script" || -e /etc/systemd/system/kvpn-node-backup.timer || \
        -e /etc/systemd/system/kvpn-node-backup.service ]]; then
    die 'An existing K-VPN node backup script/timer exists; refusing to overwrite it.'
  fi
  install -d -m 700 /root/server-backups
  install -m 700 "$ROOT_DIR/lib/backup-node.sh" "$script"
  cat > /etc/systemd/system/kvpn-node-backup.service <<'EOF'
[Unit]
Description=K-VPN Node configuration backup
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/kvpn-node-backup.sh
UMask=0077
NoNewPrivileges=yes
EOF
  cat > /etc/systemd/system/kvpn-node-backup.timer <<'EOF'
[Unit]
Description=Daily K-VPN Node backup
[Timer]
OnCalendar=*-*-* 03:30:00 UTC
Persistent=true
RandomizedDelaySec=15min
Unit=kvpn-node-backup.service
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now kvpn-node-backup.timer
  systemctl start kvpn-node-backup.service
  echo 'Backup enabled (daily ~03:30 UTC). Archives contain SECRETS, mode 600; store securely.'
}

install_decoy() {
  require_debian
  [[ -f "$STATE_DIR/node.env" ]] || die 'Provision the node first (wizard).'
  source "$STATE_DIR/node.env"
  [[ ! -e /etc/nginx/sites-enabled/kvpn-reality-decoy ]] || die 'K-VPN decoy already installed; refusing to overwrite.'
  # Dedicated mode can be run independently: do not assume curl or ss is installed.
  install_packages ca-certificates curl iproute2 libc-bin
  local domain email public_ip
  domain=$(ask_default 'Hostname for REALITY target (DNS A points to this server)' '')
  [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$domain" == *.* ]] || die 'Invalid FQDN'
  email=$(ask_default 'Email for Let’s Encrypt registration' '')
  [[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die 'Invalid email'
  echo 'Decoy requirements: DNS A -> this host; Internet TCP 80 accessible; port 9444 local-only.'
  port_unused 9444 || die 'Port 9444 is already used; refusing to modify an existing service.'
  if ! port_unused 80; then
    die 'Port 80 is in use. This mode only supports standalone ACME on a fresh host.'
  fi
  public_ip=$(curl -4fsS --max-time 12 --noproxy '*' https://api.ipify.org || true)
  if [[ -n "$public_ip" ]]; then
    if ! getent ahostsv4 "$domain" | awk '{print $1}' | grep -Fxq "$public_ip"; then
      die "DNS A for $domain does not point to detected public IP $public_ip"
    fi
  else
    warn 'Could not determine external IP. Verify DNS manually before proceeding.'
    confirm 'Proceed with certificate request?' || die 'Cancelled'
  fi
  if command -v ufw >/dev/null && ufw status | grep -qi '^Status: active'; then
    if ! ufw status | grep -Eq '^80/tcp[[:space:]]+ALLOW'; then
      confirm 'Allow public TCP 80 for ACME certificate issuance and renewal?' || die 'ACME requires TCP 80'
      ufw allow 80/tcp comment 'KVPN ACME HTTP-01 renewal'
    fi
  fi
  confirm "Request Let's Encrypt certificate for $domain and install nginx on localhost:9444?" || die 'Cancelled'
  install_packages certbot nginx
  # apt may have started nginx on port 80; only stop after confirming fresh host.
  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    if [[ -L /etc/nginx/sites-enabled/default && $(readlink -f /etc/nginx/sites-enabled/default) == /etc/nginx/sites-available/default ]]; then
      rm /etc/nginx/sites-enabled/default
      systemctl stop nginx || true
    else
      die 'Custom nginx default site detected; refusing to modify it.'
    fi
  fi
  if ! port_unused 80; then die 'Port 80 still in use; use manual ACME configuration.'; fi
  if [[ ! -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]]; then
    certbot certonly --standalone --preferred-challenges http -d "$domain" --agree-tos --no-eff-email --non-interactive -m "$email"
  fi
  install -d -m 755 /var/www/kvpn-reality
  printf '%s\n' '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><body><h1>Welcome</h1></body></html>' \
    > /var/www/kvpn-reality/index.html
  # Dedicated IPv4 loopback listener; not available from the public Internet.
  cat > /etc/nginx/sites-available/kvpn-reality-decoy <<EOF
server {
    listen 127.0.0.1:9444 ssl;
    server_name $domain;
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    root /var/www/kvpn-reality;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
    access_log off;
}
EOF
  ln -s /etc/nginx/sites-available/kvpn-reality-decoy /etc/nginx/sites-enabled/kvpn-reality-decoy
  install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/kvpn-nginx-reload.sh <<'EOF'
#!/bin/sh
if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then
  systemctl reload nginx
fi
EOF
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/kvpn-nginx-reload.sh
  nginx -t
  systemctl enable --now nginx
  systemctl restart nginx
  curl -fsS --noproxy '*' --resolve "$domain:9444:127.0.0.1" "https://$domain:9444/" -o /dev/null
  echo "HTTPS decoy OK: $domain on local 127.0.0.1:9444"
  echo 'NEXT: In Remnawave Panel set REALITY dest/target=127.0.0.1:9444 and serverNames/SNI to this domain.'
  echo 'Ensure port 80 remains available for automatic Certbot HTTP-01 renewal.'
}

status() {
  echo '=== NODE ==='
  if [[ -f "$NODE_DIR/docker-compose.yml" ]] && command -v docker >/dev/null; then
    (cd "$NODE_DIR" && docker compose ps) || true
  else
    echo 'No installed Node compose in /opt/remnanode'
  fi
  echo '=== FIREWALL ==='
  command -v ufw >/dev/null && ufw status || true
  echo '=== TIMERS ==='
  systemctl list-timers --all --no-pager 2>/dev/null | grep -E 'kvpn-(node|monitor)' || true
  echo '=== SSH, NGINX, TLS ==='
  command -v ss >/dev/null && ss -lnt | grep -E ':(22|80|443|2222|8443|9444)( |$)' || true
  command -v nginx >/dev/null && nginx -t 2>&1 | tail -2 || true
}

diagnostics() {
  local out="${1:-/root/kvpn-node-diagnostics-$(date -u +%Y%m%d-%H%M%S).txt}"
  [[ "$out" == /* ]] || die 'Diagnostics path must be absolute'
  [[ ! -e "$out" ]] || die 'Diagnostics destination already exists'
  { echo 'K-VPN Node Deployer diagnostics (NO tokens/keys/compose contents)'
    date -u
    uname -a
    cat /etc/os-release
    echo '--- system resources ---'
    command -v uptime >/dev/null && uptime || true
    command -v free >/dev/null && free -h || true
    command -v df >/dev/null && df -h / || true
    echo '--- selected ports ---'
    if command -v ss >/dev/null; then
      ss -lnt | grep -E ':(22|80|443|2222|8443|9444|10000)( |$)' || true
    fi
    echo '--- docker status (no environment or compose) ---'
    if command -v docker >/dev/null; then docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' || true; fi
    echo '--- firewall ---'
    if command -v ufw >/dev/null; then ufw status || true; fi
    echo '--- KVPN systemd timers ---'
    systemctl list-timers --all --no-pager | grep -E 'kvpn-|NEXT' || true
    echo '--- systemd probe services ---'
    systemctl is-active kvpn-node-backup.timer kvpn-monitor-kit-probe.timer 2>/dev/null || true
  } > "$out"
  chmod 600 "$out"
  echo "Diagnostics saved: $out (review before sharing; IPs may be visible)"
}

# Menu is the DEFAULT interactive entry point. Every action is independent;
# only the full wizard installs multiple components in one run.
menu() {
  require_debian
  require_root
  [[ -r /dev/tty ]] || die 'Interactive terminal required for menu'
  local choice role
  while true; do
    cat <<'MENU'

=========================================
          K-VPN Node Deployer
=========================================
 1) Install Remnawave Node ONLY (UFW must be ready)
 2) Configure UFW ONLY (new VPS)
 3) Install Docker + Compose ONLY
 4) Full installation wizard (NEW VPS)
 5) Setup local HTTPS REALITY target
 6) Setup daily backups
 7) Install monitoring PANEL (NEW panel only)
 8) Install RU monitoring agent
 9) Install FOREIGN monitoring agent
10) Register probe on monitoring panel
11) Server status
12) Read-only preflight
13) Save diagnostics
14) Add RU IP to foreign node UFW (existing installer-managed node)
 0) Exit
MENU
    choice=$(ask_default 'Choose an action' '0')
    case "$choice" in
      1) install_node node_only;;
      2) configure_firewall_only;;
      3) require_debian; install_docker;;
      4) install_node full;;
      5) install_decoy;;
      6) install_backup;;
      7) (cd "$ROOT_DIR/monitor-kit" && ./install.sh panel);;
      8) (cd "$ROOT_DIR/monitor-kit" && ./install.sh ru);;
      9) (cd "$ROOT_DIR/monitor-kit" && ./install.sh foreign);;
      10) (cd "$ROOT_DIR/monitor-kit" && ./install.sh register);;
      11) status;;
      12) preflight;;
      13) diagnostics;;
      14) add_ru_firewall_source;;
      0) return 0;;
      *) warn 'Unknown menu item';;
    esac
  done
}

main() {
  local cmd="${1:-menu}"
  case "$cmd" in
    help|-h|--help) usage;;
    menu) menu;;
    preflight) preflight;;
    node) require_root; install_node node_only;;
    firewall) require_root; configure_firewall_only;;
    firewall-add-ru) require_root; add_ru_firewall_source;;
    docker) require_root; require_debian; install_docker;;
    wizard) require_root; install_node full;;
    decoy) require_root; install_decoy;;
    backup) require_root; install_backup;;
    monitor)
      require_root
      [[ -n "${2:-}" ]] || die 'Specify panel|ru|foreign|register|status'
      (cd "$ROOT_DIR/monitor-kit" && ./install.sh "$2")
      ;;
    status) status;;
    diagnostics) require_root; diagnostics "${2:-}";;
    *) usage; exit 2;;
  esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
