"""Publish verified offline staging into a fresh, locally reserved Docker volume."""

import os
from pathlib import Path
import secrets
import stat
import subprocess
import time

from ..errors import Denied
from .protocol import SHA256, text
from .resource_archive import _NAME
from .resource_restore_target import _RESTORE_LABEL, _get, check_restore_target
from .storage import process_lock


_DOCKER = Path("/usr/bin/docker")
_SOCKET = Path("/run/docker.sock")
_ROOT = Path("/var/lib/docker")
_LOCK = Path("/run/hostorbit-resource-restore.lock")
_IMAGE = "docker.io/library/python@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928"
_COPY = '''
set -eu
entry=$(find /volume -mindepth 1 -maxdepth 1 -print -quit)
test -z "$entry"
cp -a /restore/. /volume/
sync -f /volume
'''


def _require_private_docker():
    try:
        socket, parent, binary = _SOCKET.lstat(), _SOCKET.parent.lstat(), _DOCKER.stat()
        if (os.geteuid() != 0 or not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0
                or stat.S_IMODE(socket.st_mode) != 0o600 or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != 0 or parent.st_mode & 0o022 or not stat.S_ISREG(binary.st_mode)
                or binary.st_uid != 0 or binary.st_mode & 0o022):
            raise Denied("RESTORE_DOCKER_PRIVATE_DAEMON_REQUIRED")
    except OSError:
        raise Denied("RESTORE_DOCKER_PRIVATE_DAEMON_REQUIRED") from None


def _docker(configuration, *args, timeout=15):
    _require_private_docker()
    command = [str(_DOCKER), "--config", str(configuration), "--host", f"unix://{_SOCKET}", *args]
    try:
        result = subprocess.run(command, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        return result.stdout.decode("ascii").strip()
    except subprocess.TimeoutExpired:
        raise Denied("RESTORE_DOCKER_OUTCOME_UNKNOWN", 503) from None
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        raise Denied("RESTORE_DOCKER_COMMAND_FAILED", 503) from None


def _copy_to_volume(directory, name, target, procedure):
    preflight = check_restore_target(name, **target)
    container = _docker(directory, "create", "--name", "hostorbit-restore-" + target["reservation"],
                        "--label", f"{_RESTORE_LABEL}={target['reservation']}",
                        "--pull=never", "--network=none", "--read-only", "--user=0:0",
                        "--security-opt=no-new-privileges", "--cap-drop=ALL", "--cap-add=CHOWN",
                        "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER", "--log-driver=none",
                        "--mount", f"type=bind,src={directory / 'data'},dst=/restore,readonly",
                        "--mount", f"type=volume,src={name},dst=/volume,volume-nocopy",
                        "--entrypoint=/bin/sh", _IMAGE, "-c", _COPY)
    text(container, SHA256, "RESTORE_DOCKER_CONTAINER_INVALID")
    try:
        check_restore_target(name, **target, expected_container=container,
                             expected_fingerprint=preflight["target_fingerprint"])
        if not procedure["tested_at"] <= int(time.time()) < procedure["expires_at"]:
            raise Denied("RESTORE_ATTESTATION_EXPIRED")
    except Denied:
        try:
            _docker(directory, "rm", container)
        except Denied:
            pass  # A running or unreachable helper needs operator reconciliation.
        raise
    # From dispatch onward, preserve the helper and its volume on failure.
    try:
        _docker(directory, "start", "--attach", container, timeout=300)
        outcome = _docker(directory, "container", "inspect", "--format",
                          "{{.State.Status}} {{.State.ExitCode}}", container)
    except Denied:
        raise Denied("RESTORE_DOCKER_OUTCOME_UNKNOWN", 503) from None
    if outcome != "exited 0":
        raise Denied("RESTORE_DOCKER_COPY_FAILED", 503)
    _docker(directory, "rm", container)


def publish_staged_volume(destination, name, staged):
    """Use the private data tree produced by this invocation's offline restore."""
    text(name, _NAME, "RESTORE_TARGET_UNTRUSTED")
    directory = Path(destination)
    text(str(directory), r"/[A-Za-z0-9_./-]+", "RESTORE_DOCKER_STAGING_PATH_UNSUPPORTED")
    info = directory.lstat()
    if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or staged["status"] != "RESTORE_STAGED"):
        raise Denied("RESTORE_DOCKER_STAGING_UNTRUSTED")
    _require_private_docker()
    endpoint = "/volumes/" + name
    with process_lock(_LOCK):
        try:
            _get(_SOCKET, 0, endpoint)
        except Denied as error:
            if error.code != "RESTORE_TARGET_NOT_FOUND":
                raise
        else:
            raise Denied("RESTORE_DOCKER_TARGET_EXISTS", 409)
        reservation = secrets.token_hex(16)
        if _docker(directory, "volume", "create", "--driver=local",
                   "--label", f"{_RESTORE_LABEL}={reservation}", name) != name:
            raise Denied("RESTORE_DOCKER_RESERVATION_UNKNOWN", 503)
        volume = _get(_SOCKET, 0, endpoint)
        archive = staged["archive"]
        inodes = archive["entries"] + 1
        block = os.statvfs(_ROOT).f_frsize
        target = {"expected_created_at": volume.get("CreatedAt"), "reservation": reservation,
                  "required_bytes": archive["bytes"] + inodes * block, "required_inodes": inodes}
        _copy_to_volume(directory, name, target, staged["procedure"])
    return {**staged, "status": "RESTORE_WRITTEN", "volume": name, "reservation": reservation,
            "restore_eligibility": "SOURCE_ARCHIVE_ELIGIBLE", "application_verification": "REQUIRED"}
