"""A real chrooted OpenSSH SFTP receiver in a disposable network namespace."""

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import subprocess
import time


def run(*args, check=True):
    value = subprocess.run([str(x) for x in args], capture_output=True, timeout=20)
    if check and value.returncode:
        raise RuntimeError("SFTP fixture command failed: " + Path(str(args[0])).name)
    return value


@dataclass
class Receiver:
    root: Path
    store: Path
    account: str
    host_key: str
    namespace: str
    config: Path
    log: object
    process: object = None

    def start(self):
        self.process = subprocess.Popen(["/usr/sbin/ip", "netns", "exec", self.namespace,
                                         "/usr/sbin/sshd", "-D", "-e", "-f", str(self.config)],
                                        stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        until = time.monotonic() + 10
        while time.monotonic() < until:
            try:
                with socket.create_connection(("10.241.0.2", 2223), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("SFTP fixture listener did not start")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)


@contextmanager
def receiver(root, public_key):
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("SFTP namespace fixture requires the disposable hosted VM")
    root.chmod(0o711)
    base = root / "sftp-receiver"
    base.mkdir(mode=0o755)
    base.chmod(0o755)
    namespace, link, peer = "hostorbit-sftp-lab", "ho-sftp-host", "ho-sftp-peer"
    if namespace in run("/usr/sbin/ip", "netns", "list").stdout.decode():
        raise RuntimeError("SFTP fixture namespace already exists")
    account = "ho-sftp-" + secrets.token_hex(3)
    created, mounted, created_namespace, obj = False, False, False, None
    log = (base / "sshd.log").open("wb")
    try:
        run("/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/store", "--no-create-home",
            "--shell", "/bin/sh", "--password", "*", account)
        created = True
        user = pwd.getpwnam(account)
        jail = base / "jail"
        jail.mkdir(mode=0o755)
        jail.chmod(0o755)
        store = jail / "store"
        store.mkdir(mode=0o700)
        run("/usr/bin/mount", "-t", "tmpfs", "-o", "size=2m,mode=0700", "tmpfs", store)
        mounted = True
        os.chown(store, user.pw_uid, user.pw_gid)
        (base / "authorized").write_text(public_key.strip() + "\n")
        (base / "authorized").chmod(0o644)
        run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", base / "host")
        host_key = " ".join((base / "host.pub").read_text().split()[:2])
        run("/usr/sbin/ip", "netns", "add", namespace)
        created_namespace = True
        run("/usr/sbin/ip", "link", "add", link, "type", "veth", "peer", "name", peer)
        run("/usr/sbin/ip", "link", "set", peer, "netns", namespace)
        run("/usr/sbin/ip", "addr", "add", "10.241.0.1/30", "dev", link)
        run("/usr/sbin/ip", "link", "set", link, "up")
        run("/usr/sbin/ip", "-n", namespace, "addr", "add", "10.241.0.2/30", "dev", peer)
        run("/usr/sbin/ip", "-n", namespace, "link", "set", peer, "up")
        run("/usr/sbin/ip", "-n", namespace, "link", "set", "lo", "up")
        Path("/run/sshd").mkdir(exist_ok=True)
        config = base / "sshd.conf"
        config.write_text(f'''Port 2223
ListenAddress 10.241.0.2
HostKey {base}/host
PidFile {base}/sshd.pid
UsePAM no
StrictModes yes
PermitRootLogin no
AllowUsers {account}
AuthorizedKeysFile {base}/authorized
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitUserEnvironment no
PermitUserRC no
DisableForwarding yes
PermitTTY no
ChrootDirectory {jail}
ForceCommand internal-sftp -d /store
Subsystem sftp internal-sftp
''')
        config.chmod(0o600)
        run("/usr/sbin/sshd", "-t", "-f", config)
        obj = Receiver(base, store, account, host_key, namespace, config, log)
        obj.start()
        yield obj
    finally:
        if obj is not None:
            obj.stop()
        if created:
            run("/usr/bin/pkill", "-u", account, check=False)
        if mounted:
            run("/usr/bin/umount", base / "jail/store", check=False)
        if created_namespace:
            run("/usr/sbin/ip", "netns", "del", namespace, check=False)
            run("/usr/sbin/ip", "link", "del", link, check=False)
        if created:
            run("/usr/sbin/userdel", account, check=False)
        log.close()
