"""Verify the typed restart against the disposable GitHub Actions Docker daemon."""

import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit


def main():
    if (len(sys.argv) != 2 or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not re.fullmatch(r"docker\.io/library/python@sha256:[0-9a-f]{64}", sys.argv[1])):
        raise SystemExit("Requires disposable GitHub-hosted Docker and a pinned fixture image")
    host = os.environ["DOCKER_HOST"]
    address = urlsplit(host)
    if address.scheme != "unix" or address.netloc or not address.path.startswith("/") or address.query or address.fragment:
        raise SystemExit("Requires a local Docker daemon")
    socket = Path(address.path).resolve(strict=True)
    remote = Path(__file__).resolve().parents[2] / "remote"
    helper = runpy.run_path(str(remote / "typed-helper"))
    restart = runpy.run_path(str(remote / "docker-restart"))

    def docker(*args):
        return subprocess.check_output(["/usr/bin/docker", "--host", host, *args], text=True, timeout=90).strip()

    target = docker("run", "-d", "--network", "none", "--read-only", "--cap-drop", "ALL",
                    "--ipc", "private", "--cgroupns", "private", "--runtime", "runc", "--log-driver", "local",
                    "--label", "com.docker.compose.project=restart-lab", "--label", "com.docker.compose.service=fixture",
                    "--user", "65534:65534", "--entrypoint", "python", sys.argv[1], "-c", "import time; time.sleep(90)")
    try:
        with TemporaryDirectory(dir=socket.parent) as name:
            root = Path(name)
            protected_socket = root / "docker.sock"
            os.link(socket, protected_socket)
            policy = root / "restart.json"
            scope = {"id": target, "project": "restart-lab", "service": "fixture"}
            policy.write_text(json.dumps({"v": 1, "containers": [scope]}))
            policy.chmod(0o600)
            journal = root / "journal"
            journal.mkdir(mode=0o700)
            boot = restart["BOOT_ID"]
            before = helper["inspect_container"](protected_socket, scope)["State"]["StartedAt"]
            request = {"operation_id": "A" * 26, "container_id": target, "boot_id": boot.read_text().strip(),
                       "started_at": before}
            kwargs = {"socket_path": protected_socket, "discovery": policy, "policy": policy,
                      "journal": journal, "boot_id": boot}
            assert restart["restart_once"](request, helper, **kwargs) == ("SUCCEEDED", "DOCKER_RESTART_VERIFIED")
            after = helper["inspect_container"](protected_socket, scope)["State"]["StartedAt"]
            assert restart["timestamp"](after) > restart["timestamp"](before)
            assert restart["restart_once"](request, helper, **kwargs) == ("SUCCEEDED", "RESTART_ALREADY_VERIFIED")
            assert helper["inspect_container"](protected_socket, scope)["State"]["StartedAt"] == after
            print("Docker changed StartedAt once. Replaying the same operation produced the verified receipt.")
    finally:
        docker("rm", "-f", target)


if __name__ == "__main__":
    main()
