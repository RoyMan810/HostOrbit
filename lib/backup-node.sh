#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
base=/root/server-backups
mkdir -p "$base"
chmod 700 "$base"
file="$base/kvpn-node-$(date -u +%Y-%m-%d_%H-%M-%S).tar.gz"
items=()
for path in /opt/remnanode /etc/kvpn-node-deployer /etc/nginx /etc/letsencrypt /etc/ufw /etc/ssh /etc/sysctl.d /etc/netplan /etc/fstab /etc/logrotate.d/remnanode /usr/local/sbin/kvpn-node-backup.sh /etc/kvpn-monitor; do
  [[ -e "$path" ]] && items+=("${path#/}")
done
[[ "${#items[@]}" -gt 0 ]] || { echo 'No files to back up'; exit 1; }
tmp="$file.partial.$$"
trap 'rm -f "$tmp"' EXIT
tar -C / --warning=no-file-changed -czf "$tmp" "${items[@]}"
chmod 600 "$tmp"
# Link atomically: unlike mv -n, this fails if a same-second archive exists.
ln -- "$tmp" "$file"
rm -f -- "$tmp"
(cd "$base" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")
chmod 600 "$file.sha256"
find "$base" -maxdepth 1 -type f \( -name 'kvpn-node-*.tar.gz' -o -name 'kvpn-node-*.tar.gz.sha256' \) -mtime +14 -delete
printf 'Backup complete: %s\n' "$file"
