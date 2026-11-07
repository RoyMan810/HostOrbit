"""A single fixed OpenSSH operation; credentials never leave the Broker boundary."""

import fcntl
import os
import select
import signal
import subprocess
import time

from ..errors import Denied
from .protocol import canonical, decode, fields, integer, text
from .storage import new_private_file, protected_bytes


PROBE_REQUEST = b'{"operation":"probe","version":1}\n'
PROBE_COMMAND = "hostorbit.v1.probe"


def _key_fd(key):
    fd = os.memfd_create("hostorbit-ssh", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(key)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _bounded_process(argv, *, key_fd, payload, timeout=12):
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               pass_fds=(key_fd,), start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"})
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        process.stdin.write(payload)
        process.stdin.close()
        streams = {process.stdout: output, process.stderr: errors}
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Denied("SSH_TIMEOUT")
            readable, _, _ = select.select(list(streams), [], [], min(remaining, 0.2))
            for stream in readable:
                chunk = os.read(stream.fileno(), 1024)
                if not chunk:
                    stream.close()
                    del streams[stream]
                else:
                    streams[stream].extend(chunk)
                    if len(streams[stream]) > 2048:
                        raise Denied("SSH_UNSUPPORTED_OUTPUT")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(output), bytes(errors)
    except (OSError, subprocess.SubprocessError):
        raise Denied("SSH_CONNECTION_FAILED") from None
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def probe(target, private_key, known_hosts):
    key = _key_fd(private_key)
    try:
        argv = ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-i", f"/proc/self/fd/{key}", "-p", str(target.value["port"])]
        options = {"BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none", "ConnectTimeout": "4",
                   "ConnectionAttempts": "1", "StrictHostKeyChecking": "yes", "HostKeyAlias": f"ho-{target.id}",
                   "UserKnownHostsFile": str(known_hosts), "GlobalKnownHostsFile": "/dev/null", "PasswordAuthentication": "no",
                   "KbdInteractiveAuthentication": "no", "ClearAllForwardings": "yes", "PermitLocalCommand": "no", "LogLevel": "ERROR"}
        for name, value in options.items():
            argv.extend(("-o", f"{name}={value}"))
        argv.extend((f'hostorbit-svc@{target.value["ip"]}', PROBE_COMMAND))
        code, output, errors = _bounded_process(argv, key_fd=key, payload=PROBE_REQUEST)
    finally:
        os.close(key)
    if code != 0:
        if b"REMOTE HOST IDENTIFICATION HAS CHANGED" in errors or b"Host key verification failed" in errors:
            raise Denied("SSH_HOST_KEY_MISMATCH")
        raise Denied("SSH_CONNECTION_FAILED")
    # No generic stdout/stderr is ever returned, stored, or included in an exception.
    value = decode(output.rstrip(b"\n"))
    fields(value, ("v", "uid", "boot_id", "observed_at"))
    if type(value["v"]) is not int or value["v"] != 1 or type(value["uid"]) is not int or value["uid"] != 0:
        raise Denied("SSH_PROBE_INVALID")
    text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    integer(value["observed_at"], int(time.time()) - 300, int(time.time()) + 2)
    return {"status": "REACHABLE", "source": "restricted_helper", "observed_at": value["observed_at"], "boot_id": value["boot_id"]}


def provision_known_hosts(path, policy):
    data = "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode()
    new_private_file(path, data)


def verify_known_hosts(path, policy):
    expected = "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode()
    if protected_bytes(path, owner=os.geteuid(), exact_mode=0o600) != expected:
        raise Denied("SSH_PINNED_KEYS_INVALID")
