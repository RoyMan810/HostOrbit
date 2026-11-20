"""Prepare an Ubuntu VPS for VPN-Orbit inventory using interactive OpenSSH."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PROBE_ACCOUNT = "vpn-orbit-svc"
PROBE_HOME = "/var/lib/vpn-orbit-ssh/vpn-orbit-svc"
LIBEXEC = "/usr/local/libexec/vpn-orbit"
SSH_CONFIG = "/etc/ssh/sshd_config.d/60-vpn-orbit-probe.conf"
SUDOERS = "/etc/sudoers.d/vpn-orbit-probe"
AUTHORIZED = "/etc/ssh/vpn-orbit-keys/vpn-orbit-svc"
SSH_PROFILE = f"""Match User {PROBE_ACCOUNT}
    AuthorizedKeysFile {AUTHORIZED}
    ForceCommand {LIBEXEC}/ssh-gateway
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no

Match all
"""


def identifier():
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = secrets.randbits(128)
    return "".join(alphabet[(value >> shift) & 31] for shift in range(125, -1, -5))


def identify_host(ip, port, expected):
    lines = subprocess.check_output(
        ["ssh-keyscan", "-T", "5", "-t", "ed25519", "-p", str(port), ip],
        text=True, stderr=subprocess.DEVNULL,
    )
    keys = {tuple(line.split()[1:]) for line in lines.splitlines() if line and not line.startswith("#")}
    if len(keys) != 1:
        raise ValueError("Could not identify a single Ed25519 host key")
    algorithm, encoded = next(iter(keys))
    key = base64.b64decode(encoded, validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    if algorithm != "ssh-ed25519" or fingerprint != expected:
        raise ValueError(f"SSH host fingerprint mismatch (received {fingerprint})")
    return f"{algorithm} {encoded}"


def install_file(path, contents, mode):
    encoded = base64.b64encode(contents).decode()
    validate = '/usr/sbin/visudo -cf "$work/file"\n' if path == SUDOERS else ""
    return (f'printf %s {shlex.quote(encoded)} | base64 -d > "$work/file"\n'
            f'{validate}'
            f'if [ -e {path} ] || [ -L {path} ]; then test ! -L {path}; cmp -s "$work/file" {path}; fi\n'
            f'install -o root -g root -m {mode} "$work/file" {path}')


def provision(probe_public_key):
    payload = {
        f"{LIBEXEC}/ssh-gateway": ((ROOT / "remote/ssh-gateway").read_bytes(), "0755"),
        f"{LIBEXEC}/typed-helper": ((ROOT / "remote/typed-helper").read_bytes(), "0755"),
        AUTHORIZED: (f'restrict,command="{LIBEXEC}/ssh-gateway" '.encode() + probe_public_key, "0644"),
        SUDOERS: (f'{PROBE_ACCOUNT} ALL=(root) NOPASSWD: {LIBEXEC}/typed-helper ""\n'.encode(), "0440"),
        SSH_CONFIG: (SSH_PROFILE.encode(), "0644"),
    }
    commands = "\n".join(install_file(path, contents, mode) for path, (contents, mode) in payload.items())
    # Dedicated accounts and files prevent an existing interactive user from
    # acquiring the helper's privileges and make a same-key retry predictable.
    return f"""set -eu
umask 077
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test -d /etc/ssh/sshd_config.d
systemctl is-active --quiet ssh.service
/usr/sbin/sshd -t
if id {PROBE_ACCOUNT} >/dev/null 2>&1; then
    test "$(getent passwd {PROBE_ACCOUNT} | cut -d: -f6,7)" = {PROBE_HOME}:/bin/sh
    test "$(passwd -S {PROBE_ACCOUNT} | cut -d' ' -f2)" = L
else
    useradd --system --user-group --no-create-home --home-dir {PROBE_HOME} --shell /bin/sh {PROBE_ACCOUNT}
fi
install -d -o root -g root -m 0755 {PROBE_HOME} {LIBEXEC} /etc/ssh/vpn-orbit-keys
work=$(mktemp -d)
new_ssh_profile=false
if [ ! -e {SSH_CONFIG} ] && [ ! -L {SSH_CONFIG} ]; then new_ssh_profile=true; fi
trap 'rm -f "$work/file"; rmdir "$work"' EXIT
{commands}
if ! /usr/sbin/sshd -t ||
   ! /usr/sbin/sshd -T -C "user={PROBE_ACCOUNT},addr=$1,host=localhost" |
        grep -Fxq 'forcecommand {LIBEXEC}/ssh-gateway' ||
   ! systemctl reload ssh.service; then
    if "$new_ssh_profile"; then rm -f -- {SSH_CONFIG}; fi
    exit 1
fi
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=ipaddress.ip_address, help="Numeric VPS IP")
    parser.add_argument("--user", required=True, help="Existing SSH administrator with sudo")
    parser.add_argument("--port", default=22, type=int)
    parser.add_argument("--fingerprint", required=True, help="Ed25519 SHA256 fingerprint from the VPS console")
    parser.add_argument("--identity", type=Path, help="Administrator's SSH private key. Omit for an interactive password.")
    parser.add_argument("--output", required=True, type=Path, help="Private directory for the managed key and Controller policy")
    args = parser.parse_args()
    if (not isinstance(args.host, ipaddress.IPv4Address) or args.host.is_loopback or args.host.is_link_local
            or args.host.is_unspecified or args.host.is_multicast or str(args.host) == "100.100.100.200"
            or not 1 <= args.port <= 65535 or not re.fullmatch(r"[a-z_][a-z0-9_-]*", args.user)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", args.fingerprint)):
        parser.error("Provide a non-loopback IPv4 address, SSH port, administrator and Ed25519 fingerprint")
    if args.identity is not None and not args.identity.is_file():
        parser.error("Administrator identity file does not exist")
    ip = str(args.host)
    os.umask(0o077)
    try:
        host_key = identify_host(ip, args.port, args.fingerprint)
        key = args.output.resolve() / "probe"
        policy = args.output / "targets.json"
        scope = {"ip": ip, "port": args.port, "allowed_cidrs": [ip + "/32"], "host_key": host_key,
                 "policy_revision": 1, "dependencies": [], "capabilities": ["host.probe"]}
        if args.output.exists():
            output_stat = args.output.lstat()
            if (args.output.is_symlink() or not args.output.is_dir() or output_stat.st_uid != os.getuid()
                    or output_stat.st_mode & 0o077):
                raise ValueError("Output directory must be private and owned by the current user")
            value = json.loads(policy.read_text())
            target, = value["targets"]
            if any(target.get(name) != value for name, value in scope.items()):
                raise ValueError("The saved policy belongs to a different VPS")
            if any(not path.is_file() or path.is_symlink() for path in (key, key.with_suffix(".pub"))):
                raise ValueError("The saved observation key pair is missing")
        else:
            args.output.mkdir(mode=0o700)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            target = {**scope, "id": identifier(), "secret_ref": identifier() + ":v1"}
            policy.write_text(json.dumps({"v": 1, "targets": [target]}, indent=2) + "\n")
        with tempfile.TemporaryDirectory(prefix="vpn-orbit-ssh-") as tmp:
            known_hosts = Path(tmp, "known_hosts")
            host = ip if args.port == 22 else f"[{ip}]:{args.port}"
            known_hosts.write_text(f"{host} {host_key}\n")
            ssh = ["ssh", "-F", "/dev/null", "-p", str(args.port), "-o", "StrictHostKeyChecking=yes",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known_hosts}",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=10"]
            if args.identity is None:
                auth = ["-o", "PreferredAuthentications=keyboard-interactive,password"]
            else:
                auth = ["-i", str(args.identity), "-o", "IdentitiesOnly=yes",
                        "-o", "PreferredAuthentications=publickey"]
            remote = shlex.join(["sudo", "--", "/bin/sh", "-c",
                                 provision(key.with_suffix(".pub").read_bytes()), "vpn-orbit-provision"])
            remote += ' "${SSH_CONNECTION%% *}"'
            subprocess.run([*ssh, "-t", *auth, f"{args.user}@{ip}", remote], check=True)
            result = subprocess.check_output(
                [*ssh, "-T", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                 f"{PROBE_ACCOUNT}@{ip}", "vpn-orbit.v8.probe"],
                input='{"operation":"probe","version":8}\n', text=True,
            )
            observation = json.loads(result)
            if not isinstance(observation, dict) or observation.get("v") != 8 or observation.get("uid") != 0:
                raise ValueError("Unexpected response from the VPN-Orbit observation gateway")
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"VPS preparation failed: {exc}\n" if not isinstance(exc, subprocess.CalledProcessError)
                    else f"VPS preparation failed (command exited with status {exc.returncode}).\n")
    print(f"SSH observation verified. Controller policy: {args.output / 'targets.json'}")
    print(f"Resource ID: {target['id']} · Secret Reference: {target['secret_ref']}")
    print(f"Managed key for Broker import: {key}")


if __name__ == "__main__":
    main()
