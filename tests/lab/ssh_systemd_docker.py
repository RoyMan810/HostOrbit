"""Run the delegated-effect experiment through the restricted SSH fixture."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile

from docker_late_effect import docker, exercise, kill_client, wait_for
from ssh_restart_fixture import COMMAND, DOCKER_HOST, REQUEST, local_docker_socket


def systemctl(*args, check=True):
    result = subprocess.run(
        ["/usr/bin/systemctl", *args], timeout=6, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        raise RuntimeError(f"systemctl {args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def unit_state(unit):
    output = systemctl("show", "-p", "ActiveState", "-p", "MainPID", "-p", "ControlGroup", unit)
    return dict(line.split("=", 1) for line in output.splitlines())


def empty_cgroup(group):
    try:
        return "populated 0" in (group / "cgroup.events").read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return True


def experiment(lab, port, helper_dir, authorized_keys, image, daemon):
    state_dir = helper_dir / "restart-fixture"
    state_dir.mkdir(mode=0o700)
    probe_gateway = helper_dir / "probe-gateway"
    fixture = Path(__file__).with_name("ssh_restart_fixture.py")
    unit = f"hostorbit-stage0-restart-{secrets.token_hex(8)}.service"
    ssh = [
        "/usr/bin/ssh", "-F", "/dev/null", "-p", str(port), "-i", str(lab / "client"),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=2",
        "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={lab / 'known_hosts'}",
        "-T", "hostorbit-svc@127.0.0.1", COMMAND,
    ]

    def launch(container):
        (state_dir / "spec.json").write_text(
            json.dumps({"container": container, "unit": unit, "docker_host": daemon}), encoding="ascii",
        )
        with TemporaryFile() as request:
            request.write(REQUEST)
            request.seek(0)
            return subprocess.Popen(ssh, stdin=request, stdout=subprocess.DEVNULL)

    def stop_remote(client, container):
        receipt = (state_dir / "receipt").read_text(encoding="ascii")
        if receipt != f"{container} {unit}\n":
            raise RuntimeError("Unexpected typed helper receipt")
        running = unit_state(unit)
        cgroup = running["ControlGroup"]
        if running["ActiveState"] != "active" or running["MainPID"] == "0" or cgroup != f"/system.slice/{unit}":
            raise RuntimeError("Docker client was not running inside the expected transient unit")
        group = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        if running["MainPID"] not in (group / "cgroup.procs").read_text(encoding="ascii").split():
            raise RuntimeError("Transient unit cgroup did not contain its Docker client")

        replay = subprocess.run(ssh, input=REQUEST, capture_output=True, timeout=5)
        if replay.returncode != 65:
            raise RuntimeError("The typed helper did not reject a second request")
        authorized_keys.write_text("", encoding="ascii")
        # Suspend the SSH client so the unit can be killed before the client exits on its own.
        client.send_signal(signal.SIGSTOP)
        try:
            (group / "cgroup.kill").write_text("1", encoding="ascii")
        finally:
            kill_client(client)
        wait_for(lambda: empty_cgroup(group), "the killed transient unit to have no processes", seconds=8)
        denied = subprocess.run(ssh, input=REQUEST, capture_output=True, timeout=5)
        if denied.returncode != 255 or b"Permission denied (publickey)" not in denied.stderr:
            raise RuntimeError("The revoked fixture SSH key was not denied at authentication")
        print(f"SSH was lost, the fixture key was revoked and cgroup {cgroup} is empty.", flush=True)

    try:
        shutil.copyfile(helper_dir / "ssh-gateway", probe_gateway)
        probe_gateway.chmod(0o644)
        for name in ("ssh-gateway", "typed-helper"):
            path = helper_dir / name
            shutil.copyfile(fixture, path)
            path.chmod(0o755)
        with TemporaryDirectory(prefix="remote-effect-", dir=lab) as directory:
            exercise(Path(directory), image, launch_restart=launch, stop_remote=stop_remote)
    finally:
        try:
            systemctl("stop", unit, check=False)
            systemctl("reset-failed", unit, check=False)
        finally:
            probe_gateway.unlink(missing_ok=True)
            shutil.rmtree(state_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lab", type=Path)
    parser.add_argument("port", type=int)
    parser.add_argument("helper_dir", type=Path)
    parser.add_argument("authorized_keys", type=Path)
    args = parser.parse_args()
    daemon = os.environ.get("HOSTORBIT_LAB_DOCKER_HOST", DOCKER_HOST)
    if not local_docker_socket(daemon):
        parser.error("The fixture requires a local Docker Unix socket")
    os.environ["DOCKER_HOST"] = daemon
    os.environ.pop("DOCKER_CONTEXT", None)
    image = os.environ["HOSTORBIT_LAB_PYTHON_IMAGE"]
    print(docker("version", "--format", "Docker Engine {{.Server.Version}}"))
    docker("pull", "--platform", "linux/amd64", image, timeout=90)
    experiment(args.lab, args.port, args.helper_dir, args.authorized_keys, image, daemon)


if __name__ == "__main__":
    main()
