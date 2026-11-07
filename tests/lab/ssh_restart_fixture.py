#!/usr/bin/python3 -I
"""Gateway and typed helper installed only by the SSH/systemd fault-injection lab."""

import json
import os
from pathlib import Path
import re
import runpy
import signal
import sys


COMMAND = "hostorbit.stage0.restart-fixture"
REQUEST = b'{"operation":"restart-fixture","target":"stage0-fixture","version":1}\n'
DOCKER_HOST = "unix:///var/run/docker.sock"


def local_docker_socket(address):
    if not re.fullmatch(r"unix:///[A-Za-z0-9_./-]+\.sock", address):
        return False
    path = Path(address.removeprefix("unix://"))
    return ".." not in path.parts and path.is_socket()


def restart_fixture(state_dir: Path, *, payload: bytes | None = None, stop_timeout: int = 25) -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        return 65
    if payload is None:
        signal.alarm(5)
        payload = sys.stdin.buffer.read(len(REQUEST) + 1)
        signal.alarm(0)
    if payload != REQUEST:
        return 65

    spec = json.loads((state_dir / "spec.json").read_text(encoding="ascii"))
    container, unit, daemon = spec["container"], spec["unit"], spec["docker_host"]
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        return 65
    if not re.fullmatch(r"hostorbit-stage0-restart-[0-9a-f]{16}\.service", unit):
        return 65
    if not local_docker_socket(daemon):
        return 65
    try:
        with (state_dir / "receipt").open("x", encoding="ascii") as receipt:
            receipt.write(f"{container} {unit}\n")
            receipt.flush()
            os.fsync(receipt.fileno())
    except FileExistsError:
        return 65
    directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

    systemd_run = "/usr/bin/systemd-run"
    os.execv(systemd_run, [
        systemd_run, "--quiet", "--wait", f"--unit={unit}", "--property=Type=exec",
        "--property=KillMode=control-group", "--property=RuntimeMaxSec=40s",
        "--property=TimeoutStopSec=4s", "--", "/usr/bin/docker", "--host", daemon,
        "container", "restart", "--timeout", str(stop_timeout), container,
    ])


def main() -> int:
    installed = Path(__file__)
    if installed.name == "ssh-gateway":
        gateway = runpy.run_path(str(installed.with_name("probe-gateway")))
        return gateway["forward"](COMMAND, REQUEST, timeout=45)
    if installed.name == "typed-helper":
        return restart_fixture(installed.with_name("restart-fixture"))
    return 65


if __name__ == "__main__":
    raise SystemExit(main())
