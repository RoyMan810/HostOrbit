#!/usr/bin/env python3
"""Destructive, disposable-VM-only integration of distinct Linux identities and real SSH."""

import argparse
from contextlib import ExitStack
import errno
import grp
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

from hostorbit.auth import AuthService, COOKIE
from hostorbit.database import DataAccess, Store, identifier
from hostorbit.errors import Denied
from hostorbit.queue import JobQueue
from hostorbit.runtime.cli import configuration, run
from hostorbit.runtime.ipc import Client
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.storage import new_private_file


REPO = Path(__file__).resolve().parents[2]
UID_API, UID_WORKER, UID_BROKER, UID_STRANGER = 23101, 23102, 23103, 23105
GID_APP, GID_BROKER_RPC, GID_GATE_RPC = 23201, 23202, 23203
TARGET, SECRET = "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "01JCYQZ4T9V8MNVYEH3D2M7Q1C"
ORIGIN = "https://hostorbit.test"


def command(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=15, **kwargs)
    if result.returncode:
        # These child commands never print credentials; Broker suppresses raw SSH output itself.
        print(result.stderr.decode(errors="replace")[-4000:], file=sys.stderr)
        result.check_returncode()
    return result


def wait_for(check, message, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = check()
            if result:
                return result
        except (OSError, sqlite3.Error, httpx.HTTPError, Denied):
            pass
        time.sleep(0.1)
    raise RuntimeError(message)


def child(args):
    config = configuration(args.config)
    if args.child == "access":
        values = {}
        for name, path in (("gate", config["gate_socket"]), ("broker", config["broker_socket"])):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                try:
                    client.connect(path)
                    values[name] = 0
                except OSError as error:
                    values[name] = error.errno
        for name, path in (("vault", Path(config["vault_directory"]) / "vault.sqlite3"), ("gate_journal", Path(config["supervisor_directory"]) / "gate.sqlite3"), ("credential", config["vault_credential"])):
            try:
                Path(path).read_bytes()
                values[name] = 0
            except OSError as error:
                values[name] = error.errno
        print(json.dumps(values))
        return
    if args.child == "rpc":
        request = json.loads(sys.stdin.read())
        endpoint = config["gate_socket"] if request["service"] == "gate" else config["broker_socket"]
        try:
            value = Client(endpoint, server_uids={0, UID_BROKER}).call(request["operation"], request["payload"])
            print(json.dumps({"ok": True, "result": value}))
        except Denied as error:
            print(json.dumps({"ok": False, "code": error.code}))
        return
    if args.listener_fd is not None:
        if args.listener_fd != 3:
            os.dup2(args.listener_fd, 3)
            os.close(args.listener_fd)
        os.environ["LISTEN_PID"] = str(os.getpid())
        os.environ["LISTEN_FDS"] = "1"
    if args.child == "import-key":
        from hostorbit.runtime.vault import Vault
        vault = Vault(config["vault_directory"], config["vault_credential"])
        vault.import_ssh(SECRET, 1, Path(args.key).read_bytes(), owner_id=args.owner, worker_uid=UID_WORKER, target=TARGET)
        return
    return run(config, args.child, once=args.once)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--child")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--listener-fd", type=int)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--key")
    parser.add_argument("--owner")
    args = parser.parse_args()
    if args.child:
        child(args)
        return
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted VM")
    account = "hostorbit-svc"
    try:
        pwd.getpwnam(account)
    except KeyError:
        pass
    else:
        raise SystemExit("Fixture account already exists")
    helper_dir = Path("/usr/local/libexec/hostorbit")
    sudoers = Path("/etc/sudoers.d/hostorbit_stage1_ssh")
    if helper_dir.exists() or sudoers.exists():
        raise SystemExit("Fixture paths already exist")
    tag = secrets.token_hex(4)
    namespace, host_link, remote_link = f"ho-runtime-{tag}", f"hoh{tag}", f"hor{tag}"
    processes = []
    logs = []
    user_created = network_created = helper_created = sudoers_created = False
    service_users, service_groups = [], []
    with tempfile.TemporaryDirectory(prefix="hostorbit-runtime-", dir="/run") as temp:
        lab = Path(temp)
        lab.chmod(0o755)
        code = lab / "code"
        code.mkdir(mode=0o755)
        shutil.copytree(REPO / "hostorbit", code / "hostorbit", ignore=shutil.ignore_patterns("__pycache__"))
        child_script = code / "tests_runtime" / "lab" / Path(__file__).name
        child_script.parent.mkdir(parents=True, mode=0o755)
        shutil.copyfile(Path(__file__), child_script)
        for item in code.rglob("*"):
            item.chmod(0o755 if item.is_dir() else 0o644)
        def role_options(role):
            return {"api": dict(user=UID_API, group=GID_APP, extra_groups=[]),
                    "worker": dict(user=UID_WORKER, group=UID_WORKER, extra_groups=[GID_APP, GID_BROKER_RPC, GID_GATE_RPC]),
                    "broker": dict(user=UID_BROKER, group=UID_BROKER, extra_groups=[GID_GATE_RPC]),
                    "stranger": dict(user=UID_STRANGER, group=UID_STRANGER, extra_groups=[GID_BROKER_RPC]),
                    "root": dict(user=0, group=0, extra_groups=[])}[role]
        config_path = lab / "runtime.json"
        def service_env(role):
            # A foreign launcher HOME must not enable implicit SSH trust/key discovery in Broker.
            name = {"api": "ho-api", "worker": "ho-worker", "broker": "ho-broker", "root": "root", "stranger": "nobody"}[role]
            return {**os.environ, "PYTHONPATH": str(code), "HOME": "/root" if role in ("root", "broker") else "/nonexistent",
                    "USER": name, "LOGNAME": name}
        def invoke(mode, role, *extra, input=None):
            return command(sys.executable, str(child_script), "--child", mode, "--config", str(config_path), *extra,
                           input=input, cwd=code, env=service_env(role), **role_options(role))
        def spawn(mode, role, *, listener=None):
            stream = (lab / f"{mode}-{len(processes)}.log").open("wb")
            logs.append(stream)
            argv = [sys.executable, str(child_script), "--child", mode, "--config", str(config_path)]
            if listener:
                argv += ["--listener-fd", str(listener.fileno())]
            process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
                                       pass_fds=(listener.fileno(),) if listener else (), cwd=code, env=service_env(role), **role_options(role))
            processes.append(process)
            return process
        def stop(process):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        try:
            for name, gid in (("ho-app-db", GID_APP), ("ho-broker-rpc", GID_BROKER_RPC), ("ho-gate-rpc", GID_GATE_RPC),
                              ("ho-worker", UID_WORKER), ("ho-broker", UID_BROKER)):
                try:
                    grp.getgrnam(name)
                    raise RuntimeError("Fixture group already exists")
                except KeyError:
                    pass
                command("groupadd", "--gid", str(gid), name)
                service_groups.append(name)
            for name, uid, gid in (("ho-api", UID_API, GID_APP), ("ho-worker", UID_WORKER, UID_WORKER), ("ho-broker", UID_BROKER, UID_BROKER)):
                try:
                    pwd.getpwnam(name)
                    raise RuntimeError("Fixture service account already exists")
                except KeyError:
                    pass
                command("useradd", "--uid", str(uid), "--gid", str(gid), "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", name)
                service_users.append(name)
            unit_dir = lab / "verified-units"
            unit_dir.mkdir()
            for unit in (REPO / "deploy/systemd").glob("*"):
                # Verify unit syntax without requiring an installed /opt/hostorbit entry point.
                content = unit.read_text().replace("/opt/hostorbit/venv/bin/hostorbit-runtime", sys.executable)
                (unit_dir / unit.name).write_text(content)
            command("systemd-analyze", "--man=no", "verify", *(str(p) for p in unit_dir.iterdir()),
                    env={**os.environ, "SYSTEMD_UNIT_PATH": f"{unit_dir}:/usr/lib/systemd/system:/lib/systemd/system"})
            print("Systemd service/socket profiles passed the systemd syntax verifier.", flush=True)
            (lab / "remote-home").mkdir(mode=0o555)
            command("useradd", "--system", "--user-group", "--shell", "/bin/sh", "--home-dir", str(lab / "remote-home"), "--no-create-home", account)
            user_created = True
            command("usermod", "-L", account)
            helper_dir.mkdir(parents=True, mode=0o755)
            helper_created = True
            for name in ("ssh-gateway", "typed-helper"):
                shutil.copyfile(REPO / "remote" / name, helper_dir / name)
                (helper_dir / name).chmod(0o755)
            sudoers.write_text('Defaults:hostorbit-svc env_reset,secure_path="/usr/sbin:/usr/bin:/sbin:/bin"\nhostorbit-svc ALL=(root) NOPASSWD: /usr/local/libexec/hostorbit/typed-helper ""\n')
            sudoers.chmod(0o440)
            sudoers_created = True
            command("visudo", "-cf", str(sudoers))
            Path("/run/sshd").mkdir(exist_ok=True)
            for name in ("host", "client", "wrong-host"):
                command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(lab / name))
            original_host = (lab / "host").read_bytes()
            (lab / "authorized").write_text(f'restrict,command="{helper_dir}/ssh-gateway" ' + (lab / "client.pub").read_text())
            (lab / "authorized").chmod(0o644)
            command("ip", "netns", "add", namespace)
            network_created = True
            command("ip", "link", "add", host_link, "type", "veth", "peer", "name", remote_link)
            command("ip", "link", "set", remote_link, "netns", namespace)
            command("ip", "addr", "add", "10.222.0.1/30", "dev", host_link)
            command("ip", "link", "set", host_link, "up")
            command("ip", "-n", namespace, "addr", "add", "10.222.0.2/30", "dev", remote_link)
            command("ip", "-n", namespace, "link", "set", remote_link, "up")
            command("ip", "-n", namespace, "link", "set", "lo", "up")
            (lab / "sshd.conf").write_text(f'''Port 2222
ListenAddress 10.222.0.2
HostKey {lab}/host
PidFile {lab}/sshd.pid
UsePAM yes
StrictModes yes
PermitRootLogin no
PermitUserEnvironment no
AllowUsers {account}
AuthenticationMethods publickey
Match User {account}
    AuthorizedKeysFile {lab}/authorized
    ForceCommand {helper_dir}/ssh-gateway
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
''')
            def sshd():
                stream = (lab / f"sshd-{len(processes)}.log").open("wb")
                logs.append(stream)
                p = subprocess.Popen(["ip", "netns", "exec", namespace, "/usr/sbin/sshd", "-D", "-e", "-f", str(lab / "sshd.conf")], stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                processes.append(p)
                wait_for(lambda: socket.create_connection(("10.222.0.2", 2222), timeout=0.5).close() or True, "SSH listener did not start")
                return p
            remote = sshd()
            for name, uid, mode in (("gate", 0, 0o700), ("broker", UID_BROKER, 0o700), ("vault", UID_BROKER, 0o700)):
                (lab / name).mkdir(mode=mode)
                os.chown(lab / name, uid, uid)
            (lab / "sockets").mkdir(mode=0o755)
            for name, gid in (("gate", GID_GATE_RPC), ("broker", GID_BROKER_RPC)):
                (lab / "sockets" / name).mkdir(mode=0o710)
                os.chown(lab / "sockets" / name, 0, gid)
            source_credential = lab / "root-credentials"
            source_credential.mkdir(mode=0o700)
            dek = os.urandom(32)
            new_private_file(source_credential / "broker-dek", dek)
            new_private_file(lab / "broker-credential", dek)
            os.chown(lab / "broker-credential", UID_BROKER, UID_BROKER)
            (lab / "broker-credential").chmod(0o400)
            targets = {"v": 1, "targets": [{"id": TARGET, "ip": "10.222.0.2", "port": 2222, "allowed_cidrs": ["10.222.0.0/30"],
                       "host_key": " ".join((lab / "host.pub").read_text().split()[:2]), "secret_ref": SECRET + ":v1",
                       "policy_revision": 1, "dependencies": [], "capabilities": ["host.probe"]}]}
            (lab / "targets.json").write_bytes(canonical(targets))
            (lab / "targets.json").chmod(0o644)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                api_port = reservation.getsockname()[1]
            config = {"v": 1, "database": str(lab / "app" / "controller.sqlite3"), "app_uid": UID_API, "app_gid": GID_APP,
                      "worker_uid": UID_WORKER, "worker_gid": UID_WORKER, "broker_uid": UID_BROKER, "broker_gid": UID_BROKER,
                      "broker_rpc_gid": GID_BROKER_RPC, "gate_rpc_gid": GID_GATE_RPC, "public_origin": ORIGIN,
                      "trusted_proxies": ["127.0.0.1/32"], "api_port": api_port, "targets": str(lab / "targets.json"),
                      "supervisor_directory": str(lab / "gate"), "broker_directory": str(lab / "broker"), "vault_directory": str(lab / "vault"),
                      "vault_credential": str(lab / "broker-credential"), "public_verify_key": str(lab / "gate.pub"),
                      "gate_socket": str(lab / "sockets" / "gate" / "gate.sock"), "broker_socket": str(lab / "sockets" / "broker" / "broker.sock")}
            config_path.write_bytes(canonical(config))
            config_path.chmod(0o644)
            store = Store.initialize(Path(config["database"]), access=DataAccess(UID_API, GID_APP))
            auth = AuthService(store)
            password = secrets.token_urlsafe(24)
            owner = auth.create_owner(auth.issue_bootstrap(), "fixture-owner", password)
            invoke("initialize-supervisor", "root")
            invoke("initialize-broker", "broker")
            os.chown(lab / "client", UID_BROKER, UID_BROKER)
            invoke("import-key", "broker", "--key", str(lab / "client"), "--owner", owner)
            (lab / "client").unlink()
            invoke("register-observations", "root")
            listeners = []
            for name, owner_uid, gid in (("gate_socket", 0, GID_GATE_RPC), ("broker_socket", UID_BROKER, GID_BROKER_RPC)):
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(config[name])
                os.chown(config[name], owner_uid, gid)
                os.chmod(config[name], 0o660)
                listener.listen(16)
                listeners.append(listener)
            gate_process = spawn("supervisor", "root", listener=listeners[0])
            broker_process = spawn("broker", "broker", listener=listeners[1])
            api_process = spawn("api", "api")
            for listener in listeners:
                listener.close()
            client = httpx.Client(base_url=f"http://127.0.0.1:{api_port}", timeout=15,
                                  headers={"Host": "hostorbit.test", "Origin": ORIGIN, "X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.10"})
            wait_for(lambda: client.get("/healthz").status_code == 200, "API failed to start")
            result = client.post("/api/v1/auth/login", json={"username": "fixture-owner", "password": password})
            assert result.status_code == 200, result.text
            client.headers["Cookie"] = COOKIE + "=" + result.cookies.get(COOKIE)
            client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
            def enqueue():
                response = client.post(f"/api/v1/resources/{TARGET}/observations", json={}, headers={"Idempotency-Key": secrets.token_urlsafe(20)})
                assert response.status_code == 202, response.text
                return response.json()["id"]
            def job(job_id):
                response = client.get(f"/api/v1/jobs/{job_id}")
                assert response.status_code == 200, response.text
                return response.json()
            def rpc(role, service, operation, payload):
                response = invoke("rpc", role, input=json.dumps({"service": service, "operation": operation, "payload": payload}).encode())
                return json.loads(response.stdout)
            # Distinct UID processes share only the application database group.
            job_id = enqueue()
            invoke("worker", "worker", "--once")
            assert job(job_id)["status"] == "SUCCEEDED", job(job_id)
            assert job(job_id)["result"]["status"] == "REACHABLE"
            software = job(job_id)["result"]["software"]
            assert software.keys() == {"docker", "nginx"}
            assert set(software.values()) <= {"PRESENT", "NOT_DETECTED", "UNKNOWN"}
            inventory = client.get(f"/api/v1/resources/{TARGET}")
            assert inventory.status_code == 200
            assert inventory.json()["observation"]["last_success"]["software"] == software
            print("Distinct API and Worker UIDs committed one verified SSH observation through Broker and host authority.", flush=True)
            print("The restricted v2 helper returned a bounded Docker/Nginx software summary through the inventory API.", flush=True)
            for role in ("api", "worker"):
                blocked = json.loads(invoke("access", role).stdout)
                for name in ("vault", "gate_journal", "credential"):
                    assert blocked[name] == errno.EACCES, (role, name, blocked)
                if role == "api":
                    assert blocked["gate"] == blocked["broker"] == errno.EACCES
            denied = rpc("stranger", "broker", "use_for_scoped_ssh", {"consumer_kind": "worker"})
            assert denied == {"ok": False, "code": "RPC_PEER_DENIED"}, denied
            denied = rpc("worker", "gate", "update.quiesce", {"kind": "application"})
            assert denied == {"ok": False, "code": "RPC_OPERATION_DENIED"}, denied
            print("DAC denied API sockets and private stores; SO_PEERCRED denied a group member spoofing Worker.", flush=True)
            with store.connect() as db:
                permit = json.loads(db.execute("SELECT permit FROM jobs WHERE id=?", (job_id,)).fetchone()[0])
            replay = rpc("worker", "broker", "use_for_scoped_ssh", {"permit": permit, "secret_ref": SECRET + ":v1"})
            assert replay == {"ok": False, "code": "PERMIT_REPLAY"}, replay
            forged = json.loads(json.dumps(permit))
            forged["claims"]["target"] = SECRET
            denied = rpc("worker", "broker", "use_for_scoped_ssh", {"permit": forged, "secret_ref": SECRET + ":v1"})
            assert denied == {"ok": False, "code": "PERMIT_SIGNATURE_INVALID"}, denied
            # An untrusted remote stdout cannot become an API/SSE/log payload.
            original_helper = (helper_dir / "typed-helper").read_bytes()
            canary = "CANARY-remote-secret-must-not-escape"
            (helper_dir / "typed-helper").write_text("#!/usr/bin/python3 -I\nprint('" + canary + "')\n")
            canary_job = enqueue()
            invoke("worker", "worker", "--once")
            assert job(canary_job)["status"] == "FAILED", job(canary_job)
            (helper_dir / "typed-helper").write_bytes(original_helper)
            events = client.get("/api/v1/events").text
            with store.connect() as db:
                exported = "\n".join(db.iterdump())
            assert canary not in events + exported
            print("Replay and signature substitution were denied; raw remote canary output did not reach SQLite or SSE.", flush=True)
            # Lose Worker while Broker is executing, then restart under the same kernel lock.
            helper = original_helper.decode().replace("value = {", "time.sleep(3)\n    value = {")
            (helper_dir / "typed-helper").write_text(helper)
            interrupted = enqueue()
            worker_process = spawn("worker", "worker")
            def dispatched():
                with sqlite3.connect(Path(config["supervisor_directory"]) / "gate.sqlite3") as db:
                    return db.execute("SELECT state FROM attempts WHERE job_id=?", (interrupted,)).fetchone() == ("DISPATCHING",)
            wait_for(dispatched, "Broker did not consume the interrupted observation permit")
            duplicate = subprocess.run([sys.executable, str(child_script), "--child", "worker", "--config", str(config_path), "--once"],
                                       capture_output=True, timeout=10, cwd=code, env=service_env("worker"), **role_options("worker"))
            assert duplicate.returncode != 0 and b"PROCESS_ALREADY_RUNNING" in duplicate.stderr, duplicate.stderr
            os.killpg(worker_process.pid, signal.SIGKILL)
            worker_process.wait(timeout=5)
            invoke("worker", "worker", "--once")
            assert job(interrupted)["status"] == "UNKNOWN_OUTCOME", job(interrupted)
            wait_for(lambda: rpc("worker", "gate", "attempt.status", {"job_id": interrupted}).get("result", {}).get("state") == "SUCCEEDED",
                     "Broker did not persist the late verified receipt")
            assert job(interrupted)["status"] == "UNKNOWN_OUTCOME"
            (helper_dir / "typed-helper").write_bytes(original_helper)
            print("Second Worker was excluded by flock; killed Worker recovered as UNKNOWN despite a late successful Broker receipt.", flush=True)
            # A changed real SSH host key is denied by the Broker's pinned known_hosts.
            stop(remote)
            (lab / "host").write_bytes((lab / "wrong-host").read_bytes())
            remote = sshd()
            mismatch = enqueue()
            invoke("worker", "worker", "--once")
            assert job(mismatch)["status"] == "FAILED", job(mismatch)
            assert job(mismatch)["reason"] == "SSH_HOST_KEY_MISMATCH", job(mismatch)
            store.verify_audit()
            print("Real SSH host-key replacement was denied and the failed observation was committed with audit/outbox.", flush=True)
            client.close()
        except BaseException:
            # Print only daemon startup diagnostics; never dump request bodies, key files or Vault data.
            for path in lab.glob("*.log"):
                data = path.read_text(errors="replace")
                if path.name.startswith("sshd-") or "Traceback" in data or "Error" in data or "error" in data:
                    print(path.name, data[-4000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                stop(process)
            for stream in logs:
                stream.close()
            if network_created:
                subprocess.run(["ip", "link", "del", host_link], capture_output=True)
                subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
            if sudoers_created:
                sudoers.unlink(missing_ok=True)
            if helper_created:
                for name in ("ssh-gateway", "typed-helper"):
                    (helper_dir / name).unlink(missing_ok=True)
                helper_dir.rmdir()
            if user_created:
                subprocess.run(["userdel", account], capture_output=True)
            for name in reversed(service_users):
                subprocess.run(["userdel", name], capture_output=True)
            for name in reversed(service_groups):
                subprocess.run(["groupdel", name], capture_output=True)


if __name__ == "__main__":
    main()
