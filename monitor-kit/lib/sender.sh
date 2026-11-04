#!/usr/bin/env bash
set -euo pipefail
PROBE_ID="${1:-}"
[[ "$PROBE_ID" =~ ^[a-z0-9][a-z0-9_-]{0,39}$ ]] || { echo 'Invalid probe ID' >&2; exit 2; }
source "/etc/kvpn-monitor/probes/$PROBE_ID.env"
case "$CHECK_TYPE" in
  remote_tcp)
    if timeout 8 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null; then STATUS=OK; else STATUS=FAIL; fi
    ;;
  local_tcp)
    if timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1"' _ "$TARGET_PORT" 2>/dev/null; then STATUS=OK; else STATUS=FAIL; fi
    ;;
  *) echo 'Invalid CHECK_TYPE' >&2; exit 2;;
esac
printf 'Probe %s: %s (%s UTC)\n' "$PROBE_ID" "$STATUS" "$(date -u +'%F %T')"
printf '%s\n' "$STATUS" | timeout 25 ssh -T -p "$PANEL_PORT" \
  -i "/etc/kvpn-monitor/probes/$PROBE_ID.key" \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=/etc/kvpn-monitor/probes/$PROBE_ID.known_hosts" \
  -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2 \
  "kvpn-probe@$PANEL_HOST"
