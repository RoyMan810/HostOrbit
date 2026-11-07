#!/usr/bin/env python3
"""Fresh install in a disposable GitHub-hosted Ubuntu VM; never targets a user VPS."""

import argparse
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import pwd
import secrets
import select
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import time
import urllib.error
from urllib.request import Request, urlopen


REPO = Path(__file__).resolve().parents[2]
HOST_PYTHON = Path(sys.executable).resolve()
ORIGIN = "https://127.0.0.1:19449"
PORT = 18080
PASSWORD = "Fixture-Owner-password-117!"
FAKE_JOB = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"


def run(*args, check=True, input=None, timeout=60):
    result = subprocess.run([str(arg) for arg in args], input=input, capture_output=True, timeout=timeout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if check and result.returncode:
        print(result.stderr.decode(errors="replace")[-3000:], file=sys.stderr)
        raise RuntimeError(f"Fixture command failed: {Path(str(args[0])).name}")
    return result


def docker(host, *args, **kwargs):
    return run("/usr/bin/docker", "--host", host, *args, **kwargs).stdout.decode().strip()


def wait_for(check, description, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.1)
    raise RuntimeError(description)


def owner_create():
    """Exercise the actual local CLI with terminal echo disabled by getpass."""
    master, slave = pty.openpty()
    process = subprocess.Popen(["/opt/hostorbit/admin", "create-owner", "--username", "roman"],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    output, sent = b"", 0
    try:
        deadline = time.monotonic() + 20
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
            if sent == 0 and b"Owner password: " in output:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
            if sent == 1 and b"Confirm password: " in output:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
        process.wait(timeout=5)
        if process.returncode or sent != 2 or PASSWORD.encode() in output:
            raise RuntimeError("Owner terminal bootstrap failed or echoed the password")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


@contextmanager
def tls_proxy(root):
    run("/usr/bin/openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", root / "tls.key",
        "-out", root / "tls.crt", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in ("host", "content-length", "connection", "x-forwarded-for", "x-forwarded-proto")}
            headers.update({"Host": "127.0.0.1:19449", "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})
            request = Request(f"http://127.0.0.1:{PORT}" + self.path, data=body if self.command == "POST" else None,
                              headers=headers, method=self.command)
            try:
                response = urlopen(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() not in ("connection", "transfer-encoding", "content-length", "server", "date"):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        do_GET = forward
        do_POST = forward

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "tls.crt", root / "tls.key")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19449), Proxy)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ssl.create_default_context(cafile=str(root / "tls.crt"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--docker-host", required=True)
    args = parser.parse_args()
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted Ubuntu VM")
    # Refuse to clean up anything unless all installation namespaces are absent.
    for path in ("/opt/hostorbit", "/etc/hostorbit", "/var/lib/hostorbit", "/run/hostorbit",
                 "/etc/tmpfiles.d/hostorbit.conf", "/etc/sysusers.d/hostorbit.conf"):
        if Path(path).exists():
            raise SystemExit("Fixture installation namespace already exists")
    base = [str(HOST_PYTHON), str(REPO / "deploy/installer.py"), "install", "--bundle", str(args.bundle),
            "--trust-key", str(args.trust_key), "--development", "--origin", ORIGIN,
            "--port", str(PORT), "--docker-host", args.docker_host]
    with tempfile.TemporaryDirectory(prefix="hostorbit-install-lab-", dir="/run") as temp:
        root = Path(temp)
        # Independent trust root, not a public key automatically accepted from the bundle.
        trusted = root / "trusted.pub"
        trusted.write_bytes(args.trust_key.read_bytes())
        trusted.chmod(0o600)
        base[base.index("--trust-key") + 1] = str(trusted)
        foreign = socket.socket()
        foreign.bind(("127.0.0.1", 443))
        foreign.listen()
        foreign_identity = foreign.fileno()
        installed = False
        try:
            # Complete cryptographic preflight must not create an installation.
            run(*base, "--check", timeout=90)
            if Path("/opt/hostorbit").exists():
                raise RuntimeError("Preflight created persistent installation state")
            print("Signed bundle preflight passed without creating application state.", flush=True)
            response = run(*base, timeout=420)
            result = json.loads(response.stdout)
            if result.get("recovery") != "NOT_READY" or result.get("installed") is not True:
                raise RuntimeError("Installation reported false readiness")
            installed = True
            metadata = json.loads(Path("/opt/hostorbit/installation.json").read_bytes())
            cfg = json.loads(Path("/etc/hostorbit/runtime.json").read_bytes())
            ids = {name: docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file",
                               "/etc/hostorbit/compose.json", "ps", "--quiet", name) for name in ("api", "worker")}
            entries = {name: json.loads(docker(args.docker_host, "inspect", identity))[0] for name, identity in ids.items()}
            if entries["api"]["Image"] != metadata["image_id"] or entries["worker"]["Image"] != metadata["image_id"]:
                raise RuntimeError("Unverified image executed")
            if entries["worker"]["HostConfig"]["NetworkMode"] != "none" or not entries["api"]["HostConfig"]["ReadonlyRootfs"]:
                raise RuntimeError("Installed namespace isolation differs from the contract")
            published = entries["api"]["NetworkSettings"]["Ports"]["8000/tcp"]
            if published != [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}]:
                raise RuntimeError("API was not published exclusively on loopback")
            if foreign.fileno() != foreign_identity or foreign.getsockname() != ("127.0.0.1", 443):
                raise RuntimeError("Foreign listener changed")
            for service in ("hostorbit-broker.service", "hostorbit-supervisor.service", "hostorbit-compose.service"):
                if run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active":
                    raise RuntimeError("Installed systemd service is inactive")
            print("Real systemd Broker/supervisor and isolated API/Worker containers started; foreign port 443 stayed untouched.", flush=True)
            code = """import json
from hostorbit.runtime.ipc import Client
from hostorbit.errors import Denied
c=json.load(open('/etc/hostorbit/runtime.json'))
out={}
for name,operation in [('gate_socket','attempt.status'),('broker_socket','receipt.get')]:
 try: Client(c[name],server_uids={0,c['broker_uid']}).call(operation,{'job_id':'01JCYQZ4T9V8MNVYEH3D2M7Q1A'})
 except Denied as e: out[name]=e.code
print(json.dumps(out))
"""
            reached = json.loads(docker(args.docker_host, "exec", ids["worker"], "python", "-c", code))
            if reached != {"gate_socket": "ATTEMPT_NOT_FOUND", "broker_socket": "RECEIPT_NOT_TERMINAL"}:
                raise RuntimeError("Worker did not authenticate with its actual container peer credentials")
            denied = json.loads(docker(args.docker_host, "exec", ids["api"], "python", "-c", code))
            if denied != {"gate_socket": "RPC_UNAVAILABLE", "broker_socket": "RPC_UNAVAILABLE"}:
                raise RuntimeError("Backend reached a host privilege socket")
            key_path = Path("/etc/hostorbit/credentials/broker-dek")
            if key_path.stat().st_mode & 0o777 != 0o600 or key_path.stat().st_uid != 0:
                raise RuntimeError("Runtime credential source is not root-private")
            print("Worker container reached scoped IPC; Backend had neither privilege socket nor runtime credential mount.", flush=True)
            with tls_proxy(root) as context:
                def request(path, body=None):
                    request = Request(ORIGIN + path, data=None if body is None else json.dumps(body).encode(),
                                      headers={"Origin": ORIGIN, "Content-Type": "application/json"})
                    try:
                        return urlopen(request, context=context, timeout=10)
                    except urllib.error.HTTPError as error:
                        return error
                before = request("/api/v1/users", {"username": "visitor", "password": PASSWORD, "role": "Owner"})
                if before.status not in (401, 422):
                    raise RuntimeError("Anonymous visitor could provision an administrator")
                with sqlite3.connect("/var/lib/hostorbit/app/controller.sqlite3") as db:
                    if db.execute("SELECT count(*) FROM users").fetchone() != (0,):
                        raise RuntimeError("Installation unexpectedly created an Owner")
                owner_create()
                login = request("/api/v1/auth/login", {"username": "roman", "password": PASSWORD})
                if login.status != 200 or "Secure" not in login.headers.get("Set-Cookie", ""):
                    raise RuntimeError("Installed Owner could not authenticate through HTTPS proxy")
                login.close()
            print("First web visitor had no bootstrap authority; hidden-input local Owner setup and HTTPS login passed.", flush=True)
            before = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/hostorbit/credentials/broker-dek"),
                ("gate", "/var/lib/hostorbit/control-gate/signing.key"))}
            again = run(*base, check=False, timeout=30)
            if again.returncode == 0:
                raise RuntimeError("Second install replaced a live installation")
            after = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/hostorbit/credentials/broker-dek"),
                ("gate", "/var/lib/hostorbit/control-gate/signing.key"))}
            if before != after:
                raise RuntimeError("Second install changed private keys")
            run("/usr/bin/systemctl", "restart", "hostorbit-compose.service", timeout=150)
            if json.load(urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=5))["status"] != "alive":
                raise RuntimeError("Compose service did not recover after restart")
            print("Repeated install was denied without key replacement; systemd Compose restart preserved the installation.", flush=True)
        except Exception:
            for service in ("hostorbit-broker.service", "hostorbit-supervisor.service", "hostorbit-compose.service"):
                result = run("/usr/bin/journalctl", "--unit", service, "--no-pager", "--lines", "40", check=False)
                print(result.stdout.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            foreign.close()
            # This job owns the entire disposable VM. Preserve failed install
            # state/logs until the runner is discarded; never wipe a user VPS.
            if installed:
                run("/usr/bin/systemctl", "stop", "hostorbit-compose.service", check=False, timeout=40)
                docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file",
                       "/etc/hostorbit/compose.json", "down", timeout=60)


if __name__ == "__main__":
    main()
