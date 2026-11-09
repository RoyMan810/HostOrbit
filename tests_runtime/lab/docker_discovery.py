"""Exercise the scoped Docker read adapter on a disposable GitHub runner."""

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
from urllib.parse import urlsplit
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not re.fullmatch(r"docker\.io/library/python@sha256:[0-9a-f]{64}", args.image)):
        parser.error("a disposable GitHub-hosted VM and pinned lab image are required")
    host = os.environ["DOCKER_HOST"]
    address = urlsplit(host)
    if address.scheme != "unix" or address.netloc or not address.path.startswith("/") or address.query or address.fragment:
        parser.error("a local Docker daemon socket is required")
    socket_path = Path(address.path).resolve(strict=True)
    helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote" / "typed-helper"))
    observe = helper["observe_docker"]
    prefix = "ho-discovery-" + uuid4().hex[:10]
    ids = []

    def docker(*values):
        return subprocess.check_output(["docker", "--host", host, *values], text=True, timeout=45).strip()

    def create(project, service):
        identity = docker("create", "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges=true", "--user", "65534:65534",
                          "--label", "com.docker.compose.project=" + project,
                          "--label", "com.docker.compose.service=" + service,
                          "--label", "fixture.secret=label-canary",
                          "--entrypoint", "python", args.image, "-c", "import time; time.sleep(30)")
        assert re.fullmatch(r"[0-9a-f]{64}", identity)
        ids.append(identity)
        return identity

    try:
        running = create(prefix, "web")
        stopped = create(prefix, "worker")
        foreign = create(prefix + "-foreign", "private")
        docker("start", running)
        scope = [{"id": running, "project": prefix, "service": "web"},
                 {"id": stopped, "project": prefix, "service": "worker"}]
        # The action's parent directory belongs to the runner. A hard link on
        # the same filesystem exposes the same socket in a root-owned directory.
        with tempfile.TemporaryDirectory(prefix="ho-docker-", dir=socket_path.parent) as directory:
            registry = Path(directory) / "docker-discovery.json"
            protected_socket = Path(directory) / "docker.sock"
            os.link(socket_path, protected_socket)
            registry.write_text(json.dumps({"v": 1, "containers": scope}))
            registry.chmod(0o600)
            result = observe(registry, protected_socket)
            assert result == {"status": "OBSERVED", "containers": [
                {**scope[0], "state": "RUNNING"}, {**scope[1], "state": "CREATED"},
            ]}, result
            assert foreign not in json.dumps(result) and "label-canary" not in json.dumps(result)
            wrong = [{**scope[0], "project": prefix + "-wrong"}]
            registry.write_text(json.dumps({"v": 1, "containers": wrong}))
            assert observe(registry, protected_socket) == {"status": "OBSERVED", "containers": [
                {**wrong[0], "state": "UNKNOWN"},
            ]}
            protected_socket.unlink()
            protected_socket.symlink_to(socket_path)
            assert observe(registry, protected_socket) == {"status": "UNAVAILABLE", "containers": []}
            registry.chmod(0o644)
            assert observe(registry, protected_socket) == {"status": "POLICY_INVALID", "containers": []}
            registry.unlink()
            assert observe(registry, protected_socket) == {"status": "NOT_CONFIGURED", "containers": []}
        print("Pinned Docker returned only approved full IDs and typed running/created states. Scope and label mismatches fail closed.")
    finally:
        if ids:
            docker("rm", "-f", *ids)


if __name__ == "__main__":
    main()
