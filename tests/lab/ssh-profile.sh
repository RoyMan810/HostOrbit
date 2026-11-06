#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ ${1-} != --isolated-vm || $# -gt 2 || ( $# -eq 2 && ${2-} != --docker-chain ) || $(id -u) != 0 ]]; then
    echo 'Run as root in a disposable Ubuntu 24.04 VM with --isolated-vm [--docker-chain].' >&2
    exit 2
fi
source /etc/os-release
test "$ID:$VERSION_ID" = "ubuntu:24.04"

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
account=hostorbit-svc
helper_dir=/usr/local/libexec/hostorbit
keys_dir=/etc/ssh/authorized_keys
key_file="$keys_dir/$account"
policy=/etc/sudoers.d/hostorbit_stage0_ssh
for path in "$helper_dir" "$key_file" "$policy"; do
    if [[ -e $path || -L $path ]]; then
        printf 'Fixture path already exists: %s\n' "$path" >&2
        exit 2
    fi
done
if getent passwd "$account" >/dev/null || getent group "$account" >/dev/null; then
    echo 'Fixture account or group already exists.' >&2
    exit 2
fi

lab=$(mktemp -d /run/hostorbit-ssh-lab.XXXXXX)
sshd_pid=
account_created=no
helper_dir_created=no
keys_dir_created=no
cleanup() {
    set +e
    if [[ -n $sshd_pid ]]; then
        kill "$sshd_pid" 2>/dev/null
        wait "$sshd_pid" 2>/dev/null
    fi
    rm -f -- "$key_file" "$policy"
    if [[ $helper_dir_created == yes ]]; then
        rm -f -- "$helper_dir/ssh-gateway" "$helper_dir/typed-helper"
        rmdir -- "$helper_dir"
    fi
    if [[ $keys_dir_created == yes ]]; then
        rmdir -- "$keys_dir"
    fi
    if [[ $account_created == yes ]]; then
        userdel "$account"
    fi
    rm -r -- "$lab"
}
trap cleanup EXIT

chmod 0711 "$lab"
install -d -m 0555 "$lab/home"
useradd --system --user-group --shell /bin/sh --home-dir "$lab/home" --no-create-home "$account"
account_created=yes
usermod -L "$account"
test "$(getent passwd "$account" | cut -d: -f7)" = /bin/sh
test "$(id -Gn "$account")" = "$account"

mkdir -p /usr/local/libexec /run/sshd
install -d -m 0755 "$helper_dir"
helper_dir_created=yes
if [[ ! -d $keys_dir ]]; then
    install -d -m 0755 "$keys_dir"
    keys_dir_created=yes
fi
install -m 0755 "$repo/stage0/ssh_gateway.py" "$helper_dir/ssh-gateway"
install -m 0755 "$repo/stage0/ssh_typed_helper.py" "$helper_dir/typed-helper"

cat > "$lab/sudoers" <<'POLICY'
Defaults:hostorbit-svc env_reset,secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
hostorbit-svc ALL=(root) NOPASSWD: /usr/local/libexec/hostorbit/typed-helper ""
POLICY
visudo -cf "$lab/sudoers"
install -m 0440 "$lab/sudoers" "$policy"

ssh-keygen -q -t ed25519 -N '' -f "$lab/host"
ssh-keygen -q -t ed25519 -N '' -f "$lab/client"
public_key=$(cat "$lab/client.pub")
printf 'restrict,command="%s/ssh-gateway" %s\n' "$helper_dir" "$public_key" > "$lab/authorized"
install -m 0644 "$lab/authorized" "$key_file"

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
cat > "$lab/sshd_config" <<CONFIG
Port $port
ListenAddress 127.0.0.1
HostKey $lab/host
PidFile $lab/sshd.pid
UsePAM yes
StrictModes yes
PermitRootLogin no
PermitUserEnvironment no
AllowUsers $account
AuthenticationMethods publickey

Match User $account
    AuthorizedKeysFile $key_file
    ForceCommand $helper_dir/ssh-gateway
    DisableForwarding yes
    PermitTTY no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitUserRC no
    X11Forwarding no
    AllowAgentForwarding no
    AllowTcpForwarding no
    PermitTunnel no
    PubkeyAuthentication yes
CONFIG
printf '[127.0.0.1]:%s %s\n' "$port" "$(cut -d' ' -f1,2 "$lab/host.pub")" > "$lab/known_hosts"
/usr/sbin/sshd -t -f "$lab/sshd_config"
/usr/sbin/sshd -D -e -f "$lab/sshd_config" > "$lab/server.log" 2>&1 &
sshd_pid=$!

client() {
    timeout 8s ssh -F /dev/null -p "$port" -i "$lab/client" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o ConnectTimeout=2 -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null \
        -o "UserKnownHostsFile=$lab/known_hosts" "$@"
}

request='{"operation":"probe","target":"stage0-fixture","version":1}'
expected='{"status":"OK","uid":0,"version":1}'
destination="$account@127.0.0.1"
typed_probe() {
    printf '%s\n' "$request" | client -T "$destination" hostorbit.stage0.probe
}

reply=
for ((attempt=0; attempt<20; attempt++)); do
    if reply=$(typed_probe 2>"$lab/client.log"); then
        break
    fi
    sleep 0.2
done
if [[ $reply != "$expected" ]]; then
    cat "$lab/client.log" "$lab/server.log" >&2
    exit 1
fi

reject() {
    local label=$1 status=0
    shift
    "$@" >"$lab/reject.out" 2>"$lab/reject.err" || status=$?
    if [[ $status == 0 || $status == 124 ]]; then
        printf 'Expected a denial for %s, got exit %s\n' "$label" "$status" >&2
        exit 1
    fi
    printf 'Denied %s\n' "$label"
}

reject "interactive shell" client -T "$destination" </dev/null
reject "remote shell syntax" client -T "$destination" 'printf injected; id' </dev/null
reject "untyped stdin" client -T "$destination" hostorbit.stage0.probe <<<'{"operation":"exec"}'
reject "target traversal" client -T "$destination" hostorbit.stage0.probe <<<'{"operation":"probe","target":"../fixture","version":1}'
reject "environment override" client -o 'SetEnv=SSH_ORIGINAL_COMMAND=hostorbit.stage0.probe' \
    -T "$destination" id <<<$request
reject "PTY" client -tt "$destination" </dev/null
[[ $(cat "$lab/reject.err") == *'PTY allocation request failed'* ]]

reject "remote forwarding" client -o ExitOnForwardFailure=yes -N -R 0:127.0.0.1:9 "$destination"
[[ $(cat "$lab/reject.err") == *'remote port forwarding failed'* ]]

reject "sudo helper arguments" sudo -u "$account" -- sudo -n "$helper_dir/typed-helper" unexpected <<<$request
reject "sudo shell" sudo -u "$account" -- sudo -n /bin/sh -c true
for path in "$key_file" "$keys_dir" "$policy" "$helper_dir" "$helper_dir/ssh-gateway" "$helper_dir/typed-helper"; do
    test "$(stat -c '%u' "$path")" = 0
    sudo -u "$account" -- test ! -w "$path"
done

# The Match policy still applies if the per-key options are missing.
printf '%s\n' "$public_key" > "$key_file"
test "$(typed_probe)" = "$expected"
reject "shell without per-key options" client -T "$destination" id </dev/null
echo 'Pinned SSH transport accepted the fixed typed probe.'

if [[ ${2-} == --docker-chain ]]; then
    install -m 0644 "$lab/authorized" "$key_file"
    PYTHONPATH="$repo" PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$repo/tests/lab/ssh_systemd_docker.py" \
        "$lab" "$port" "$helper_dir" "$key_file"
fi
