"""Run the AC-B01 delegated-effect case against a disposable Docker container."""

import json
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import subprocess
import sqlite3
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


def wait_for_late_restart(container, initial):
    def restarted():
        current = state(container)
        return current["StartedAt"] if current["Running"] and current["StartedAt"] != initial else None

    return wait_for(restarted, "daemon to complete the late restart")


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


def start_delayed_container(root, image):
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
    return volume, container


@contextmanager
def compose_fixture(root, image):
    """Actual Compose mounts/networks; logical inventory scopes stay lab-only."""
    volume = root / "volume"
    volume.mkdir()
    program = Path(__file__).with_name("delayed_container.py").resolve()
    project = f"hostorbit-stage0-{os.urandom(8).hex()}"
    spec = root / "compose.json"
    common = {"image": image, "read_only": True, "cap_drop": ["ALL"],
              "security_opt": ["no-new-privileges:true"], "userns_mode": "host",
              "user": f"{os.getuid()}:{os.getgid()}"}
    spec.write_text(json.dumps({"services": {
        "a": {**common, "command": ["python", "/lab/fixture.py"], "networks": ["shared"],
              "volumes": [f"{volume}:/fixture", f"{program}:/lab/fixture.py:ro", "data:/shared"]},
        "b": {**common, "command": ["python", "-c", "import time; time.sleep(300)"],
              "networks": ["shared"], "volumes": ["data:/shared"]},
        "independent": {**common, "command": ["python", "-c", "import time; time.sleep(300)"],
                        "network_mode": "none"}}, "networks": {"shared": {"internal": True}},
        "volumes": {"data": {}}}), encoding="utf-8")
    prefix = ("compose", "--project-name", project, "--file", str(spec))
    print(docker("compose", "version"), flush=True)
    try:
        docker(*prefix, "up", "--detach", "--no-build", timeout=60)
        containers = {name: docker(*prefix, "ps", "--quiet", name) for name in ("a", "b", "independent")}
        if any(not value for value in containers.values()) or len(set(containers.values())) != 3:
            raise RuntimeError("Expected three isolated Compose fixture containers")

        def dependencies(container):
            item, = json.loads(docker("inspect", container))
            return {*("network:" + entry["NetworkID"] for name, entry in item["NetworkSettings"]["Networks"].items()
                      if name != "none"),
                    *("volume:" + entry["Name"] for entry in item["Mounts"] if entry["Type"] == "volume")}

        a, b, independent = (dependencies(containers[name]) for name in ("a", "b", "independent"))
        shared = a & b
        if not any(ref.startswith("network:") for ref in shared) or not any(
                ref.startswith("volume:") for ref in shared) or independent:
            raise RuntimeError("Compose inventory did not prove shared network/volume and independent scope")
        print("Compose inspect proved A/B share a network and volume; independent scope has neither.", flush=True)
        yield volume, containers["a"], {"docker-host": a, "dependent-host": b, "independent-host": independent}
    finally:
        docker(*prefix, "down", "--volumes", "--timeout", "2", timeout=40)


def exercise(root, image, *, launch_restart=launch_local_restart, stop_remote=None):
    with compose_fixture(root, image) as (volume, container, topology):
        exercise_fixture(root, volume, container, topology, launch_restart, stop_remote)


def exercise_fixture(root, volume, container, topology, launch_restart, stop_remote):
    client = None
    try:
        wait_for((volume / "ready").exists, "fixture startup")
        initial = state(container)["StartedAt"]
        journal = root / "gate.sqlite3"
        gate = HostGate.create(journal, topology)
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
        affected = gate.record_quarantine("fixture-restart", decision_ref="lab-owner-quarantine")
        if affected != {"docker-host", "dependent-host"}:
            raise RuntimeError("Quarantine did not match the inspected Compose dependency closure")
        require_denied("QUARANTINED", gate.admit_remote, "dependent-host", "next")
        independent = gate.admit_remote("independent-host", "independent-probe")
        gate.report_remote(independent, FixtureObservation(True, True, True))
        for kind in UpdateKind:
            require_denied("OPEN_INCIDENT", gate.request_update, kind)
        # An application schema replacement must not replace the separate host
        # authority or turn an uncertain external effect into a clean success.
        application = root / "application.sqlite3"
        with sqlite3.connect(application) as db:
            db.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, outcome TEXT)")
            db.execute("INSERT INTO jobs VALUES('fixture-restart', 'UNKNOWN_OUTCOME')")
            db.execute("PRAGMA user_version = 1")
        application.unlink()
        with sqlite3.connect(application) as db:
            db.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, outcome TEXT)")
            db.execute("INSERT INTO jobs VALUES('fixture-restart', 'SUCCEEDED')")
            db.execute("PRAGMA user_version = 2")
        gate = HostGate(journal)
        gate.recover_after_restart()
        if gate.outcome("fixture-restart") != Outcome.UNKNOWN:
            raise RuntimeError("Application migration cleared an unresolved host authority attempt")
        require_denied("QUARANTINED", gate.admit_remote, "dependent-host", "after-migration")
        for kind in UpdateKind:
            require_denied("OPEN_INCIDENT", gate.request_update, kind)
        print("Both updaters and shared Compose scope stayed blocked across application DB replacement and supervisor restart.", flush=True)
        print("A proven independent scope proceeded only after the durable quarantine decision.", flush=True)

        (volume / "release-stop").touch()

        restarted_at = wait_for_late_restart(container, initial)
        if gate.outcome("fixture-restart") != Outcome.UNKNOWN:
            raise RuntimeError("Late observation rewrote the terminal attempt")
        require_denied("QUARANTINED", gate.admit_remote, "dependent-host", "next")
        print(f"Daemon completed after client death (StartedAt {restarted_at}); quarantine stayed active.")
    finally:
        (volume / "release-stop").touch()
        if client is not None and client.poll() is None:
            client.kill()
            client.wait(timeout=5)


if __name__ == "__main__":
    image = os.environ["HOSTORBIT_LAB_PYTHON_IMAGE"]
    print(docker("version", "--format", "Docker Engine {{.Server.Version}}"))
    docker("pull", "--platform", "linux/amd64", image, timeout=90)
    with TemporaryDirectory() as directory:
        exercise(Path(directory), image)
