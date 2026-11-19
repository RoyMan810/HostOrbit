"""Create a signed archive during an exclusive local Docker maintenance window."""

import argparse
import base64
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
from urllib.parse import urlencode

from nacl.signing import SigningKey

from ..errors import Denied
from .archive_stream import AGE_PATH, AGE_SHA256, MAX_PAYLOAD, recipient
from .protocol import ULID, canonical, text
from .rescue import _encrypted_output, harden
from .resource_archive import _MAX_ENTRIES, _MAX_MANIFEST_SIZE, _NAME, _manifest
from .resource_restore_docker import _ROOT, _SOCKET, _require_private_docker
from .resource_restore_target import _CREATED_AT, _get, _matches, _mount_id
from .storage import directory_sync, new_private_file, protected_bytes


def _stopped(name, created_at):
    volume = _get(_SOCKET, 0, "/volumes/" + name)
    expected = {"Name": name, "Driver": "local", "Scope": "local", "CreatedAt": created_at,
                "Mountpoint": str(_ROOT / "volumes" / name / "_data")}
    if not _matches(volume, expected):
        raise Denied("CAPTURE_VOLUME_MISMATCH")
    query = urlencode({"all": 1, "filters": canonical({"volume": [name]}).decode()})
    containers = _get(_SOCKET, 0, "/containers/json?" + query, list)
    if any(not isinstance(item, dict) or item.get("State") not in ("exited", "created") for item in containers):
        raise Denied("CAPTURE_SOURCE_ACTIVE")
    return sorted((text(item.get("Id"), r"[a-f0-9]{64}"), item["State"]) for item in containers)


def _metadata(info):
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def _snapshot(fd):
    entries, members, observed = [], {}, {}
    remaining = MAX_PAYLOAD
    mount = _mount_id(fd)

    def stamp(info):
        return info.st_dev, info.st_ino, info.st_ctime_ns

    def walk(directory, prefix):
        nonlocal remaining
        before = os.fstat(directory)
        observed[prefix.rstrip("/")] = stamp(before)
        if os.listxattr(directory):
            raise Denied("CAPTURE_METADATA_UNSUPPORTED")
        with os.scandir(directory) as items:
            for item in items:
                path = prefix + item.name
                if len(path) > 240 or len(entries) >= _MAX_ENTRIES:
                    raise Denied("CAPTURE_LIMIT_EXCEEDED")
                text(item.name, r"[A-Za-z0-9_.-]+", "CAPTURE_PATH_UNSUPPORTED")
                info = item.stat(follow_symlinks=False)
                is_dir = stat.S_ISDIR(info.st_mode)
                if not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    raise Denied("CAPTURE_ENTRY_UNSUPPORTED")
                # Pin the inspected inode before opening it for I/O.
                pinned = os.open(item.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    actual = os.fstat(pinned)
                    if not os.path.samestat(info, actual) or _mount_id(pinned) != mount:
                        raise Denied("CAPTURE_SOURCE_CHANGED")
                    with ExitStack() as stack:
                        child = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK)
                        stack.callback(os.close, child)
                        entry = {"path": path, "kind": "directory" if is_dir else "file", **_metadata(actual)}
                        entries.append(entry)
                        observed[path] = stamp(actual)
                        if is_dir:
                            walk(child, path + "/")
                        else:
                            if os.listxattr(child) or actual.st_size > remaining:
                                raise Denied("CAPTURE_ENTRY_UNSUPPORTED")
                            with os.fdopen(child, "rb", closefd=False) as stream:
                                data = stream.read(actual.st_size + 1)
                            if len(data) != actual.st_size:
                                raise Denied("CAPTURE_SOURCE_CHANGED")
                            entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
                            if data:
                                members["volume/" + path] = data
                            remaining -= len(data)
                        if actual.st_ctime_ns != os.fstat(child).st_ctime_ns:
                            raise Denied("CAPTURE_SOURCE_CHANGED")
                finally:
                    os.close(pinned)
        if before.st_ctime_ns != os.fstat(directory).st_ctime_ns:
            raise Denied("CAPTURE_SOURCE_CHANGED")

    root = _metadata(os.fstat(fd))
    walk(fd, "")
    # Every captured inode must still match at the boundary between scans.
    # Reopen parents one component at a time without following symlinks.
    def recheck(directory, prefix):
        if stamp(os.fstat(directory)) != observed[prefix.rstrip("/")]:
            raise Denied("CAPTURE_SOURCE_CHANGED")
        with os.scandir(directory) as items:
            for item in items:
                path = prefix + item.name
                info = item.stat(follow_symlinks=False)
                if stamp(info) != observed.get(path):
                    raise Denied("CAPTURE_SOURCE_CHANGED")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        recheck(child, path + "/")
                    finally:
                        os.close(child)

    recheck(fd, "")
    return root, entries, members


def capture_volume(name, *, created_at, source_host, application_schema, public, signing_key, destination,
                   age_path=AGE_PATH):
    text(name, _NAME)
    text(created_at, _CREATED_AT)
    text(source_host, ULID)
    text(application_schema, _NAME)
    recipient(public)
    _require_private_docker()
    destination = Path(destination)
    parent = destination.parent
    if (not destination.is_absolute() or parent.resolve(strict=True) != parent or destination.is_relative_to(_ROOT)
            or destination.name in ("", ".", "..") or parent.stat().st_uid != os.geteuid()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700 or "system.posix_acl_default" in os.listxattr(parent)):
        raise Denied("CAPTURE_DESTINATION_UNTRUSTED")
    before = _stopped(name, created_at)
    now = int(time.time())
    with ExitStack() as stack:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(_ROOT, flags)
        stack.callback(os.close, fd)
        mount = _mount_id(fd)
        for component in ("volumes", name, "_data"):
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise Denied("CAPTURE_SOURCE_UNTRUSTED")
            fd = os.open(component, flags, dir_fd=fd)
            stack.callback(os.close, fd)
            if _mount_id(fd) != mount:
                raise Denied("CAPTURE_SOURCE_UNTRUSTED")
        root, entries, members = _snapshot(fd)
        if _stopped(name, created_at) != before:
            raise Denied("CAPTURE_SOURCE_CHANGED")
    manifest = {"v": 1, "resource_type": "docker.named-volume", "application_schema": application_schema,
                "source_host": source_host, "source_volume": name, "captured_utc": now, "quiescence": "STOPPED",
                "overwrite": "new_empty_target_only", "root": root, "entries": entries}
    _manifest(manifest, now)
    raw = canonical(manifest)
    if len(raw) > _MAX_MANIFEST_SIZE:
        raise Denied("CAPTURE_LIMIT_EXCEEDED")
    members["resource/manifest.json"] = raw
    destination.mkdir(mode=0o700)
    ciphertext = destination / "volume.age"
    provenance = destination / "volume.provenance.json"
    try:
        _encrypted_output(ciphertext, public, members, age_path=age_path, tool_owner=0)
        with ciphertext.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        claims = {"v": 1, "type": "hostorbit.resource-backup", "application_schema": application_schema,
                  "manifest_sha256": hashlib.sha256(raw).hexdigest(), "recipient": public,
                  "ciphertext_sha256": digest, "ciphertext_size": ciphertext.stat().st_size,
                  "age_sha256": AGE_SHA256, "signing_key_sha256": hashlib.sha256(bytes(signing_key.verify_key)).hexdigest()}
        signature = base64.b64encode(signing_key.sign(canonical(claims)).signature).decode()
        new_private_file(provenance, canonical({"claims": claims, "signature": signature}))
        directory_sync(parent)
    except BaseException:
        provenance.unlink(missing_ok=True)
        ciphertext.unlink(missing_ok=True)
        destination.rmdir()
        directory_sync(parent)
        raise
    return {"status": "RESOURCE_ARCHIVED", "ciphertext_sha256": digest, "entries": len(entries)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("volume", "created-at", "source-host", "application-schema", "recipient"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--signing-key", required=True, type=Path, help="private 32-byte Ed25519 seed")
    parser.add_argument("--destination", required=True, type=Path, help="new directory under a private parent")
    parser.add_argument("--age-tool", type=Path, default=AGE_PATH)
    args = parser.parse_args(argv)
    try:
        harden()
        key = SigningKey(protected_bytes(args.signing_key, maximum=32, owner=0, private=True))
        result = capture_volume(args.volume, created_at=args.created_at, source_host=args.source_host,
                                application_schema=args.application_schema, public=args.recipient,
                                signing_key=key, destination=args.destination, age_path=args.age_tool)
        print(canonical(result).decode())
        return 0
    except Denied as error:
        print(error.code, file=sys.stderr)
    except (OSError, ValueError, TypeError):
        print("RESOURCE_CAPTURE_FAILED", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
