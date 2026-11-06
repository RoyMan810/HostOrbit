#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=docker.io/library/python@sha256:f3dac913ab53b78c64f26d5518fcd7043d5a1a46522d6a493b598c3ed12f62a6
lab=$(mktemp -d)
socket_dir="$lab/broker"
broker=

cleanup() {
    if [[ -n $broker ]]; then
        docker rm -f "$broker" >/dev/null
    fi
    if [[ -d $socket_dir ]]; then
        sudo rm -f -- "$socket_dir/broker.sock"
        sudo rmdir -- "$socket_dir"
    fi
    rmdir -- "$lab"
}
trap cleanup EXIT

chmod 0711 "$lab"
broker_uid=11001
worker_uid=11002
backend_uid=11003
rpc_gid=11004
stranger_uid=11005

# Only the Broker can create the socket. The RPC group gets search permission.
sudo install -d -m 2710 -o "$broker_uid" -g "$rpc_gid" "$socket_dir"
docker version --format 'Docker Engine {{.Server.Version}}'
docker pull --platform linux/amd64 "$image"
isolation=(--network none --userns host --read-only --cap-drop ALL --security-opt no-new-privileges=true)
socket_mount="type=bind,source=$socket_dir,target=/run/hostorbit-broker"
broker=$(docker run -d "${isolation[@]}" --user "$broker_uid:$broker_uid" \
    --mount "$socket_mount" \
    --mount "type=bind,source=$repo/stage0/broker_lab.py,target=/lab/broker.py,readonly" \
    "$image" python /lab/broker.py /run/hostorbit-broker/broker.sock "$worker_uid" "$worker_uid")

for ((attempt=0; attempt<50; attempt++)); do
    if sudo test -S "$socket_dir/broker.sock"; then
        break
    fi
    sleep 0.2
done
if ! sudo test -S "$socket_dir/broker.sock"; then
    docker logs "$broker"
    exit 1
fi
test "$(sudo stat -c '%a %u %g' "$socket_dir/broker.sock")" = "660 $broker_uid $rpc_gid"
printf 'Broker socket has mode 0660, owner %s and group %s\n' "$broker_uid" "$rpc_gid"

probe() {
    local uid=$1 payload=$2
    shift 2
    docker run --rm "${isolation[@]}" --user "$uid:$uid" \
        --mount "type=bind,source=$repo/tests/lab/broker_probe.py,target=/lab/probe.py,readonly" \
        "$@" "$image" python /lab/probe.py "$payload"
}

expect() {
    local expected=$1 observed
    shift
    observed=$(probe "$@")
    printf 'Peer %s gave %s (expected %s)\n' "$1" "$observed" "$expected"
    test "$observed" = "$expected"
}

probe_request='{"operation":"probe"}'
spoof='{"operation":"probe","consumer_kind":"worker"}'
expect OK "$worker_uid" "$probe_request" --group-add "$rpc_gid" --mount "$socket_mount,readonly"
expect INVALID_REQUEST "$worker_uid" "$spoof" --group-add "$rpc_gid" --mount "$socket_mount,readonly"
expect NO_SOCKET "$backend_uid" "$spoof"
expect DAC_DENIED "$backend_uid" "$spoof" --mount "$socket_mount,readonly"
expect PEER_DENIED "$stranger_uid" "$spoof" --group-add "$rpc_gid" --mount "$socket_mount,readonly"
