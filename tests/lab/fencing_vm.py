#!/usr/bin/python3 -I
"""Managed service and restricted SSH fixture for the VM fencing experiment."""

import base64
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time


MANAGED_PORT = 2223
MANAGED_HOST = "10.0.2.100"
_TOPOLOGY = {"managed": (), "unavailable": ()}
_PROBE = b'{"operation":"probe","target":"stage0-fixture","version":1}\n'
_PROBE_OK = b'{"status":"OK","uid":0,"version":1}\n'
_RESTART = b'{"operation":"restart-service-fixture","target":"stage0-fixture","version":1}\n'
_RESTART_COMMAND = "hostorbit.stage0.restart-service-fixture"
# The daemon waits through the recovery guest's cold boot. The direct client still has a short bound.
_DOCKER_STOP_TIMEOUT = 420


def systemctl(*args, check=True):
    result = subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, check=check, timeout=8)
    return result.stdout.decode("ascii").strip()


def invocation(unit):
    if systemctl("is-active", unit) != "active":
        raise RuntimeError("The managed fixture unit is inactive")
    value = systemctl("show", "--property=InvocationID", "--value", unit)
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise RuntimeError("The managed fixture has no invocation ID")
    return value


def installed_main():
    path = Path(__file__)
    docker_script = path.with_name("docker-restart-fixture")
    docker = runpy.run_path(str(docker_script)) if docker_script.is_file() else None
    if path.name == "ssh-gateway":
        forward = runpy.run_path(str(path.with_name("probe-gateway")))["forward"]
        command = os.environ.get("SSH_ORIGINAL_COMMAND")
        if docker is not None and command == docker["COMMAND"]:
            return forward(command, docker["REQUEST"], timeout=45)
        if command == _RESTART_COMMAND:
            return forward(_RESTART_COMMAND, _RESTART, timeout=20)
        return forward("hostorbit.stage0.probe", _PROBE)
    if path.name != "typed-helper" or os.geteuid() != 0 or len(sys.argv) != 1:
        return 65
    signal.alarm(5)
    docker_request = docker["REQUEST"] if docker is not None else b""
    payload = sys.stdin.buffer.read(max(len(_RESTART), len(docker_request)) + 1)
    signal.alarm(0)
    if docker is not None and payload == docker_request:
        return docker["restart_fixture"](
            path.with_name("restart-fixture"), payload=payload, stop_timeout=_DOCKER_STOP_TIMEOUT,
        )
    if payload == _PROBE:
        sys.stdout.buffer.write(_PROBE_OK)
        return 0
    if payload != _RESTART:
        return 65
    unit = path.with_name("fencing-unit").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"hostorbit-stage0-fencing-[0-9a-f]{16}\.service", unit):
        return 65
    before = invocation(unit)
    systemctl("restart", unit)
    after = invocation(unit)
    if after == before:
        return 70
    print(after)
    return 0


def ssh(identity, known_hosts, host, port, command, request):
    return subprocess.run([
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", str(port), "-i", str(identity),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=4",
        "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={known_hosts}", f"hostorbit-svc@{host}", command,
    ], input=request, capture_output=True, timeout=25)


def key_fingerprint(public):
    kind, key, *_ = public.split()
    if kind != "ssh-ed25519":
        raise ValueError("Expected a fixture Ed25519 key")
    return hashlib.sha256(base64.b64decode(key, validate=True)).hexdigest()


@dataclass(frozen=True)
class DeferredRestart:
    volume: Path
    container: str
    unit: str
    state_dir: Path
    initial: str

    def require_pending(self):
        from docker_late_effect import state
        from ssh_systemd_docker import empty_cgroup

        group = Path("/sys/fs/cgroup/system.slice") / self.unit
        if (not empty_cgroup(group) or not (self.volume / "stop-received").is_file()
                or (self.volume / "release-stop").exists() or state(self.container)["StartedAt"] != self.initial):
            raise RuntimeError("Expected the Docker effect to remain pending with an empty direct cgroup")

    def stop_direct_client(self):
        from docker_late_effect import wait_for
        from ssh_systemd_docker import empty_cgroup, running_restart_cgroup

        wait_for((self.volume / "stop-received").exists, "the Docker daemon to start stopping the container")
        group = running_restart_cgroup(self.state_dir, self.container, self.unit)
        (group / "cgroup.kill").write_text("1", encoding="ascii")
        wait_for(lambda: empty_cgroup(group), "the Docker client cgroup to empty", seconds=8)
        self.require_pending()

    def release_and_verify(self):
        from docker_late_effect import docker, wait_for, wait_for_late_restart
        from ssh_systemd_docker import empty_cgroup

        self.require_pending()
        ready = self.volume / "ready"
        ready.unlink()
        (self.volume / "release-stop").touch()
        restarted_at = wait_for_late_restart(self.container, self.initial)
        wait_for(ready.exists, "the restarted container to become ready")
        events = docker(
            "events", "--since", self.initial, "--until", str(int(time.time()) + 1),
            "--filter", f"container={self.container}", "--filter", "event=restart", "--format", "{{.Action}}",
            timeout=8,
        )
        if events.splitlines() != ["restart"]:
            raise RuntimeError("Expected one Docker restart event for the isolated fixture")
        if not empty_cgroup(Path("/sys/fs/cgroup/system.slice") / self.unit):
            raise RuntimeError("The direct Docker client cgroup is no longer empty")
        print(f"The Docker effect completed late and the container became ready ({restarted_at}).", flush=True)


@contextmanager
def deferred_restart(lab, helper_dir, image):
    from docker_late_effect import docker, start_delayed_container, state, wait_for
    from ssh_restart_fixture import DOCKER_HOST, local_docker_socket

    daemon = os.environ.get("HOSTORBIT_LAB_DOCKER_HOST", DOCKER_HOST)
    if not local_docker_socket(daemon):
        raise RuntimeError("The deferred fixture requires a local Docker Unix socket")
    os.environ["DOCKER_HOST"] = daemon
    os.environ.pop("DOCKER_CONTEXT", None)
    docker("pull", "--platform", "linux/amd64", image, timeout=90)
    state_dir = helper_dir / "restart-fixture"
    docker_script = helper_dir / "docker-restart-fixture"
    unit = f"hostorbit-stage0-restart-{secrets.token_hex(8)}.service"
    state_dir.mkdir(mode=0o700)
    container = None
    try:
        shutil.copyfile(Path(__file__).with_name("ssh_restart_fixture.py"), docker_script)
        docker_script.chmod(0o644)
        volume, container = start_delayed_container(lab, image)
        wait_for((volume / "ready").exists, "deferred Docker fixture startup")
        (state_dir / "spec.json").write_text(
            json.dumps({"container": container, "unit": unit, "docker_host": daemon}), encoding="ascii",
        )
        yield DeferredRestart(volume, container, unit, state_dir, state(container)["StartedAt"])
    finally:
        try:
            if container is not None:
                (volume / "release-stop").touch()
                systemctl("stop", unit, check=False)
                docker("container", "rm", "-f", container, timeout=35)
        finally:
            docker_script.unlink(missing_ok=True)
            shutil.rmtree(state_dir)


@dataclass(frozen=True)
class ManagedService:
    lab: Path
    port: int
    key_file: Path
    unit: str
    deferred: DeferredRestart | None

    @property
    def host_key(self):
        return " ".join((self.lab / "host.pub").read_text(encoding="ascii").split()[:2])

    @property
    def old_key(self):
        return (self.lab / "client.pub").read_text(encoding="ascii")

    def rotate(self, public):
        kind, key, *_ = public.split()
        if key_fingerprint(public) == key_fingerprint(self.old_key):
            raise RuntimeError("Recovery tried to reuse the old managed key")
        self.key_file.write_text(f"restrict {kind} {key}\n", encoding="ascii")
        result = ssh(self.lab / "client", self.lab / "known_hosts", "127.0.0.1", self.port,
                     "hostorbit.stage0.probe", _PROBE)
        if result.returncode != 255 or b"Permission denied (publickey)" not in result.stderr:
            raise RuntimeError("The retired key reached the restricted SSH command")


@contextmanager
def managed_service(lab, port, helper_dir, key_file, docker_image=None):
    unit = f"hostorbit-stage0-fencing-{secrets.token_hex(8)}.service"
    gateway, helper = helper_dir / "ssh-gateway", helper_dir / "typed-helper"
    original = {path: path.read_bytes() for path in (gateway, helper)}
    probe_gateway, spec = helper_dir / "probe-gateway", helper_dir / "fencing-unit"
    try:
        subprocess.run([
            "/usr/bin/systemd-run", "--quiet", f"--unit={unit}", "--property=Type=exec", "--",
            "/usr/bin/sleep", "infinity",
        ], check=True, timeout=8)
        spec.write_text(unit + "\n", encoding="ascii")
        probe_gateway.write_bytes(original[gateway])
        probe_gateway.chmod(0o644)
        fixture = Path(__file__).read_bytes()
        for path in (gateway, helper):
            path.write_bytes(fixture)
        experiment = deferred_restart(lab, helper_dir, docker_image) if docker_image else nullcontext()
        with experiment as deferred:
            yield ManagedService(lab, port, key_file, unit, deferred)
    finally:
        try:
            systemctl("stop", unit, check=False)
        finally:
            for path, contents in original.items():
                path.write_bytes(contents)
            probe_gateway.unlink(missing_ok=True)
            spec.unlink(missing_ok=True)


def guest_known_hosts(root, public):
    path = root / "managed-known-hosts"
    path.write_text(f"[{MANAGED_HOST}]:{MANAGED_PORT} {public}\n", encoding="ascii")
    return path


def restart(gate, identity, known_hosts, host="managed"):
    from stage0.admission import FixtureObservation, Outcome

    permit = gate.admit_remote(host, f"fixture-restart-{host}")
    if host != "managed":
        raise RuntimeError("A permit escaped the managed fixture scope")
    result = ssh(identity, known_hosts, MANAGED_HOST, MANAGED_PORT, _RESTART_COMMAND, _RESTART)
    observed = result.stdout.decode("ascii").strip()
    confirmed = result.returncode == 0 and re.fullmatch(r"[0-9a-f]{32}", observed) is not None
    if gate.report_remote(permit, FixtureObservation(confirmed, confirmed, confirmed)) != Outcome.SUCCEEDED:
        raise RuntimeError(f"The typed SSH restart failed: {result.stderr.decode('utf-8', 'replace')}")
    return observed


def source_restart(root, identity, known_hosts):
    from stage0.admission import HostGate

    gate = HostGate.create(root / "source-gate.sqlite3", _TOPOLOGY)
    return restart(gate, identity, known_hosts)


def restart_docker(gate, identity, known_hosts):
    from ssh_restart_fixture import COMMAND, REQUEST
    from stage0.admission import FixtureObservation, Outcome

    permit = gate.admit_remote("managed", "fixture-docker-restart")
    result = ssh(identity, known_hosts, MANAGED_HOST, MANAGED_PORT, COMMAND, REQUEST)
    if result.returncode == 0:
        raise RuntimeError("The deferred Docker request completed before its client was interrupted")
    observed = gate.report_remote(permit, FixtureObservation(False, False, False))
    if observed != Outcome.UNKNOWN:
        raise RuntimeError("SSH interruption incorrectly settled the Docker effect")
    return observed


def expect_denial(code, operation, *args, **kwargs):
    from stage0.admission import Denied

    try:
        operation(*args, **kwargs)
    except Denied as error:
        if str(error) == code:
            return
        raise
    raise RuntimeError(f"Expected {code}")


def recovery_gate(root, identity, known_hosts, target):
    from stage0.admission import HostGate
    from stage0.recovery import RecoveryTarget

    gate = HostGate.create(root / "recovery-gate.sqlite3", _TOPOLOGY, recovery=RecoveryTarget(**target))
    probe = ssh(identity, known_hosts, MANAGED_HOST, MANAGED_PORT, "hostorbit.stage0.probe", _PROBE)
    if probe.returncode or probe.stdout != _PROBE_OK:
        raise RuntimeError(f"The new key did not pass the restricted probe: {probe.stderr.decode('utf-8', 'replace')}")
    expect_denial("READ_ONLY_RECOVERY", restart, gate, identity, known_hosts)
    try:
        with socket.create_connection(("10.0.2.101", MANAGED_PORT), timeout=2):
            raise RuntimeError("The unavailable fixture was reachable")
    except OSError:
        return gate


def attestation(target, owner, managed, new_key, off_at, *, delegated_terminal):
    from stage0.recovery import RecoveryTarget, activation_attestation

    time.sleep(max(0, off_at + 10 - time.time()))
    observed_at = int(time.time())
    record = activation_attestation(
        RecoveryTarget(**target),
        isolation={
            "method": "power_off", "console": "GitHub Actions QEMU host", "operator": "fixture operator",
            "autostart_blocked": True, "worker_isolated": True,
            "observations": [
                {"source": "source QEMU process exited", "at_utc": off_at, "isolated": True},
                {"source": "source disk absent after recovery boot", "at_utc": observed_at, "isolated": True},
            ],
        },
        checks=dict.fromkeys(("database_integrity", "vault_integrity", "permissions_verified", "old_automation_disabled"), True),
        hosts={
            "managed": {
                "evidence": "restricted SSH denied the old key and accepted the new probe",
                "reachable": True, "credentials_rotated": True, "old_key_denied": True, "new_key_verified": True,
                "old_key_sha256": key_fingerprint(managed.old_key), "new_key_sha256": key_fingerprint(new_key),
                "direct_stopped": True, "delegated_terminal": delegated_terminal,
                "postconditions_verified": delegated_terminal,
            },
            "unavailable": {"evidence": "unreachable test endpoint", "reachable": False},
        },
    )
    return record, owner.sign(record).signature, hashlib.sha256(record).hexdigest(), observed_at


def wait_for_observation_time(observed_at):
    deadline = time.monotonic() + 10
    while int(time.time()) < observed_at:
        if time.monotonic() >= deadline:
            raise RuntimeError("The recovery guest clock is behind the host observation")
        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(installed_main())
