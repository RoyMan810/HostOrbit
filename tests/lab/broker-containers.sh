#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=${HOSTORBIT_LAB_PYTHON_IMAGE:?Set the pinned lab image}
lab=$(mktemp -d)
socket_dir="$lab/broker"
app_dir="$lab/app"
policy_dir="$lab/policy"
broker=

cleanup() {
    if [[ -n $broker ]]; then
        docker rm -f "$broker" >/dev/null
    fi
    if [[ -d $socket_dir ]]; then
        sudo rm -f -- "$socket_dir/broker.sock" "$socket_dir/permit-used"
        sudo rmdir -- "$socket_dir"
    fi
    if [[ -d $app_dir ]]; then
        sudo rm -f -- "$app_dir/plans.sqlite3" "$app_dir/plans.sqlite3-journal"
        sudo rmdir -- "$app_dir"
    fi
    if [[ -d $policy_dir ]]; then
        sudo rm -f -- "$policy_dir/grant.json" "$policy_dir/vault-canary"
        sudo rmdir -- "$policy_dir"
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
sudo install -d -m 0755 -o "$backend_uid" -g "$backend_uid" "$app_dir"
sudo install -d -m 0755 "$policy_dir"
printf 'synthetic Vault canary\n' | sudo tee "$policy_dir/vault-canary" >/dev/null
docker version --format 'Docker Engine {{.Server.Version}}'
docker pull --platform linux/amd64 "$image"
isolation=(--network none --userns host --read-only --cap-drop ALL --security-opt no-new-privileges=true)
socket_mount="type=bind,source=$socket_dir,target=/run/hostorbit-broker"
broker=$(docker run -d "${isolation[@]}" --user "$broker_uid:$broker_uid" \
    --mount "$socket_mount" \
    --mount "type=bind,source=$policy_dir,target=/lab/policy,readonly" \
    --mount "type=bind,source=$repo/stage0/broker_lab.py,target=/lab/broker.py,readonly" \
    "$image" python /lab/broker.py /run/hostorbit-broker/broker.sock "$worker_uid" "$worker_uid" \
    --fixture-grant /lab/policy/grant.json)

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

boundary=(
    --mount "type=bind,source=$repo/tests/lab/broker_boundary.py,target=/lab/boundary.py,readonly"
    --mount "type=bind,source=$repo/tests/lab/broker_probe.py,target=/lab/broker_probe.py,readonly"
)
app_mount="type=bind,source=$app_dir,target=/lab/app"
docker run --rm "${isolation[@]}" --user "$backend_uid:$backend_uid" "${boundary[@]}" \
    --mount "$app_mount" "$image" python /lab/boundary.py backend
sudo /usr/bin/python3 "$repo/tests/lab/broker_boundary.py" issue "$policy_dir/grant.json"
docker run --rm "${isolation[@]}" --user "$worker_uid:$worker_uid" --group-add "$rpc_gid" "${boundary[@]}" \
    --mount "$app_mount,readonly" --mount "$socket_mount,readonly" \
    --mount "type=bind,source=$policy_dir/grant.json,target=/lab/permit.json,readonly" \
    "$image" python /lab/boundary.py worker
