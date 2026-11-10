"""Read-only Linux preflight for an unused local Docker named volume."""

from contextlib import ExitStack, closing
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import struct
from urllib.parse import urlencode

from ..errors import Denied
from .protocol import SHA256, canonical, checksum, integer, text, unique_object
from .resource_archive import _NAME


_MAX_REPLY = 16384
_RESTORE_LABEL = "org.hostorbit.resource-restore"
_CREATED_AT = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})"


class _DockerConnection(http.client.HTTPConnection):
    def __init__(self, path, owner):
        super().__init__("docker", timeout=2)
        self.path = path
        self.owner = owner

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))
        _, uid, _ = struct.unpack("3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid != self.owner:
            raise Denied("RESTORE_DOCKER_UNTRUSTED")


def _get(socket_path, owner, endpoint, reply_type=dict):
    try:
        parent, entry = socket_path.parent.lstat(), socket_path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or parent.st_mode & 0o022
                or not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != owner or entry.st_mode & 0o002):
            raise Denied("RESTORE_DOCKER_UNTRUSTED")
        with closing(_DockerConnection(socket_path, owner)) as connection:
            connection.request("GET", "/v1.44" + endpoint, headers={"Accept": "application/json"})
            with connection.getresponse() as response:
                if response.status == 404:
                    raise Denied("RESTORE_TARGET_NOT_FOUND", 404)
                if response.status != 200:
                    raise Denied("RESTORE_DOCKER_UNAVAILABLE", 503)
                raw = response.read(_MAX_REPLY + 1)
        if len(raw) > _MAX_REPLY:
            raise ValueError("oversized Docker response")
        value = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(value, reply_type):
            raise ValueError("unexpected Docker response type")
        return value
    except (OSError, ValueError, RecursionError, http.client.HTTPException):
        raise Denied("RESTORE_DOCKER_UNAVAILABLE", 503) from None


def _matches(volume, expected):
    return (isinstance(volume, dict) and all(volume.get(key) == value for key, value in expected.items())
            and "Options" in volume and volume["Options"] in (None, {}))


def _mount_id(fd):
    for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
        if line.startswith("mnt_id:"):
            return int(line.split()[1])
    raise ValueError("missing mount identity")


def _inspect_directory(root, name, owner, required_bytes, required_inodes):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        with ExitStack() as stack:
            fd = os.open(root, flags)
            stack.callback(os.close, fd)
            mount = _mount_id(fd)
            for component in ("volumes", name, "_data"):
                parent = os.fstat(fd)
                if parent.st_uid != owner or parent.st_mode & 0o022:
                    raise Denied("RESTORE_TARGET_UNTRUSTED")
                fd = os.open(component, flags, dir_fd=fd)
                stack.callback(os.close, fd)
                if _mount_id(fd) != mount:
                    raise Denied("RESTORE_TARGET_UNTRUSTED")
            entry = os.fstat(fd)
            if entry.st_uid != owner or entry.st_mode & 0o022:
                raise Denied("RESTORE_TARGET_UNTRUSTED")
            with os.scandir(fd) as entries:
                if next(entries, None) is not None:
                    raise Denied("RESTORE_TARGET_OCCUPIED", 409)
            space = os.fstatvfs(fd)
            if (space.f_flag & os.ST_RDONLY or space.f_frsize <= 0
                    or space.f_bavail * space.f_frsize < required_bytes or space.f_favail < required_inodes):
                raise Denied("RESTORE_TARGET_CAPACITY", 409)
            if os.fstat(fd).st_ctime_ns != entry.st_ctime_ns:
                raise Denied("RESTORE_TARGET_CHANGED", 409)
            return mount, entry.st_dev, entry.st_ino, entry.st_ctime_ns
    except (OSError, ValueError):
        raise Denied("RESTORE_TARGET_UNTRUSTED") from None


def check_restore_target(name, *, expected_created_at, required_bytes, required_inodes,
                         docker_root=Path("/var/lib/docker"), socket_path=Path("/run/docker.sock"), owner=0,
                         expected_fingerprint=None, reservation=None, expected_container=None):
    """Inspect a volume or recheck its fingerprint without reserving the target."""
    if expected_fingerprint is not None:
        text(expected_fingerprint, SHA256, "RESTORE_TARGET_FINGERPRINT_INVALID")
    text(name, _NAME, "RESTORE_TARGET_UNTRUSTED")
    text(expected_created_at, _CREATED_AT, "RESTORE_TARGET_UNTRUSTED")
    integer(required_bytes, 0, 2**63 - 1)
    integer(required_inodes, 1, 2**63 - 1)
    docker_root, socket_path = Path(docker_root), Path(socket_path)
    if any(not path.is_absolute() or ".." in path.parts for path in (docker_root, socket_path)):
        raise Denied("RESTORE_TARGET_UNTRUSTED")
    expected = {"Name": name, "Driver": "local", "Scope": "local", "CreatedAt": expected_created_at,
                "Mountpoint": str(docker_root / "volumes" / name / "_data")}
    if reservation is not None:
        expected["Labels"] = {_RESTORE_LABEL: text(reservation, r"[0-9a-f]{32}")}
    if expected_container is not None:
        text(expected_container, SHA256)
        if reservation is None:
            raise Denied("RESTORE_TARGET_UNTRUSTED")
    if not _matches(_get(socket_path, owner, "/volumes/" + name), expected):
        raise Denied("RESTORE_TARGET_UNTRUSTED")
    directory = _inspect_directory(docker_root, name, owner, required_bytes, required_inodes)
    if expected_container is None:
        query = urlencode({"filters": canonical({"dangling": ["true"], "name": [name]}).decode()})
        listing = _get(socket_path, owner, "/volumes?" + query).get("Volumes")
        matching = [volume for volume in listing if _matches(volume, expected)] if isinstance(listing, list) else []
        if len(matching) != 1:
            raise Denied("RESTORE_TARGET_REFERENCED", 409)
    else:
        query = urlencode({"all": 1, "filters": canonical({"volume": [name]}).decode()})
        containers = _get(socket_path, owner, "/containers/json?" + query, list)
        if (len(containers) != 1 or not isinstance(containers[0], dict)
                or containers[0].get("Id") != expected_container or containers[0].get("State") != "created"):
            raise Denied("RESTORE_TARGET_REFERENCED", 409)
    if _inspect_directory(docker_root, name, owner, required_bytes, required_inodes) != directory:
        raise Denied("RESTORE_TARGET_CHANGED", 409)
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        raise Denied("RESTORE_TARGET_UNTRUSTED") from None
    fingerprint = checksum({"v": 1, "boot_id": boot_id, "socket": str(socket_path), "owner": owner,
                            "volume": expected, "directory": directory,
                            "required_bytes": required_bytes, "required_inodes": required_inodes})
    if expected_fingerprint is not None and expected_fingerprint != fingerprint:
        raise Denied("RESTORE_TARGET_CHANGED", 409)
    return {"status": "EMPTY_TARGET_CHECKED", "target": name, "created_at": expected_created_at,
            "target_fingerprint": fingerprint, "restore_eligibility": "NOT_EVALUATED"}
