"""Run the AC-B01 delegated-effect case against a disposable Docker container."""

import json
import os
from pathlib import Path
import signal
import subprocess
from tempfile import TemporaryDirectory
import time

from stage0.admission import Denied, FixtureObservation, HostGate, Outcome, UpdateKind


def docker(*args, timeout=15):
    result = subprocess.run(
        ["docker", *args], check=True, timeout=timeout, stdout=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def wait_for(predicate, description, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {description}")


def state(container):
    return json.loads(docker("container", "inspect", "--format", "{{json .State}}", container))


def require_denied(code, operation, *args):
    try:
        operation(*args)
    except Denied as error:
        if str(error) == code:
            return
        raise
    raise RuntimeError(f"Expected {code}")


def launch_local_restart(container):
    return subprocess.Popen(
        ["docker", "container", "restart", "--timeout", "25", container],
        stdout=subprocess.DEVNULL,
    )


def kill_client(client):
    client.kill()
    if client.wait(timeout=5) != -signal.SIGKILL:
        raise RuntimeError("Restart client exited before SIGKILL")


def exercise(root, image, *, launch_restart=launch_local_restart, stop_remote=None):
    volume = root / "volume"
    volume.mkdir()
    program = Path(__file__).with_name("delayed_container.py").resolve()
    container = docker(
        "run", "-d", "--network", "none", "--userns", "host", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,source={volume},target=/fixture",
        "--mount", f"type=bind,source={program},target=/lab/fixture.py,readonly",
        image, "python", "/lab/fixture.py",
    )
    client = None
    try:
        wait_for((volume / "ready").exists, "fixture startup")
        initial = state(container)["StartedAt"]
        journal = root / "gate.sqlite3"
        gate = HostGate.create(journal, {
            "docker-host": ("lab:shared-volume",),
            "dependent-host": ("lab:shared-volume",),
            "independent-host": (),
        })
        permit = gate.admit_remote("docker-host", "fixture-restart")
        client = launch_restart(container)
        wait_for((volume / "stop-received").exists, "daemon to send SIGTERM")
        if stop_remote is None:
            kill_client(client)
        else:
            stop_remote(client, container)
        if state(container)["StartedAt"] != initial:
            raise RuntimeError("Container restarted before the direct effect was stopped")
        print(f"Daemon accepted the restart, then the client was killed (StartedAt {initial}).")

        observed = gate.report_remote(permit, FixtureObservation(True, False, False))
        if observed != Outcome.UNKNOWN:
            raise RuntimeError("Client death incorrectly resolved the daemon effect")
        gate = HostGate(journal)
        require_denied("OPEN_INCIDENT", gate.admit_remote, "dependent-host", "next")
        gate.record_quarantine("fixture-restart", decision_ref="lab-owner-quarantine")
        require_denied("QUARANTINED", gate.admit_remote, "dependent-host", "next")
        require_denied("OPEN_INCIDENT", gate.request_update, UpdateKind.APPLICATION)
        print("Conflicting work and application update were blocked while the daemon was pending.")

        (volume / "release-stop").touch()

        def restarted():
            current = state(container)
            return current["StartedAt"] if current["Running"] and current["StartedAt"] != initial else None

        restarted_at = wait_for(restarted, "daemon to complete the late restart")
        if gate.outcome("fixture-restart") != Outcome.UNKNOWN:
            raise RuntimeError("Late observation rewrote the terminal attempt")
        require_denied("QUARANTINED", gate.admit_remote, "dependent-host", "next")
        print(f"Daemon completed after client death (StartedAt {restarted_at}); quarantine stayed active.")
    finally:
        (volume / "release-stop").touch()
        if client is not None and client.poll() is None:
            client.kill()
            client.wait(timeout=5)
        docker("container", "rm", "-f", container, timeout=35)


if __name__ == "__main__":
    image = os.environ["HOSTORBIT_LAB_PYTHON_IMAGE"]
    print(docker("version", "--format", "Docker Engine {{.Server.Version}}"))
    docker("pull", "--platform", "linux/amd64", image, timeout=90)
    with TemporaryDirectory() as directory:
        exercise(Path(directory), image)
