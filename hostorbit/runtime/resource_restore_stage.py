"""Offline staging of verified named-volume data into a private directory."""

import hashlib
import os
from pathlib import Path
import stat

from ..errors import Denied
from .archive_stream import AGE_PATH, parse_manifest
from .protocol import text
from .rescue import ciphertext_stream, decrypt, offline_profile, wipe
from .rescue_payload import unpack
from .resource_archive import _MANIFEST_PATH, _MAX_MANIFEST_SIZE, _NAME, _check_ciphertext, _claims, _manifest
from .resource_restore_attestation import verify_attestation
from .storage import directory_sync, new_private_file


def _apply_metadata(path, metadata):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchown(fd, metadata["uid"], metadata["gid"])
        os.fchmod(fd, metadata["mode"])
        os.fsync(fd)
    finally:
        os.close(fd)


def _stage(destination, manifest, members):
    destination = Path(destination)
    name = text(destination.name, _NAME, "RESTORE_STAGE_TARGET_UNTRUSTED")
    parent = destination.parent
    try:
        if not destination.is_absolute() or parent.resolve(strict=True) != parent:
            raise Denied("RESTORE_STAGE_TARGET_UNTRUSTED")
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (OSError, RuntimeError):
        raise Denied("RESTORE_STAGE_TARGET_UNTRUSTED") from None
    try:
        info = os.fstat(parent_fd)
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                or "system.posix_acl_default" in os.listxattr(parent_fd)):
            raise Denied("RESTORE_STAGE_TARGET_UNTRUSTED")
        target = Path(f"/proc/self/fd/{parent_fd}") / name
        if os.path.lexists(target):
            raise Denied("RESTORE_STAGE_TARGET_EXISTS", 409)
        space = os.fstatvfs(parent_fd)
        block = space.f_frsize
        entries = manifest["entries"]
        if (space.f_flag & os.ST_RDONLY or block <= 0 or space.f_favail < len(entries) + 2
                or space.f_bavail < 2 + sum(
                    max(1, (entry.get("size", 0) + block - 1) // block) for entry in entries)):
            raise Denied("RESTORE_STAGE_CAPACITY", 409)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise Denied("RESTORE_STAGE_TARGET_EXISTS", 409) from None
        os.fsync(parent_fd)
        pending = target / "pending"
        pending.mkdir(mode=0o700)
        # Create parents before files and apply directory metadata after children.
        ordered = sorted(entries, key=lambda entry: entry["path"].count("/"))
        for entry in ordered:
            path = pending / entry["path"]
            if entry["kind"] == "directory":
                path.mkdir(mode=0o700)
            else:
                new_private_file(path, members.get("volume/" + entry["path"], b""))
                _apply_metadata(path, entry)
        for entry in reversed(ordered):
            if entry["kind"] == "directory":
                _apply_metadata(pending / entry["path"], entry)
        _apply_metadata(pending, manifest["root"])
        pending.rename(target / "data")
        try:
            directory_sync(target)
        except OSError:
            raise Denied("RESTORE_STAGE_PUBLICATION_UNKNOWN", 503) from None
    except OSError:
        raise Denied("RESTORE_STAGE_WRITE_FAILED", 503) from None
    finally:
        os.close(parent_fd)


def stage_restore_source(ciphertext, provenance, archive_key, identity, *, destination,
                         attestation, evidence, owner_key, application_schema, procedure_sha256, now,
                         age_path=AGE_PATH, tool_owner=0):
    """Materialize verified data in a new private offline staging directory."""
    offline_profile()
    if archive_key == owner_key:
        raise Denied("RESTORE_ATTESTATION_SEPARATE_OWNER_KEY_REQUIRED")
    procedure = verify_attestation(attestation, evidence, owner_key, application_schema=application_schema,
                                   procedure_sha256=procedure_sha256, now=now)
    claims = _claims(provenance, archive_key)
    if claims["application_schema"] != application_schema:
        raise Denied("RESOURCE_ARCHIVE_INCOMPATIBLE")

    plaintext = None
    try:
        with ciphertext_stream(ciphertext) as source:
            _check_ciphertext(source, claims)
            plaintext = decrypt(source, identity, age_path=age_path, tool_owner=tool_owner)
            _check_ciphertext(source, claims)
        members = unpack(plaintext)
        raw = members.pop(_MANIFEST_PATH, None)
        if (raw is None or len(raw) > _MAX_MANIFEST_SIZE
                or hashlib.sha256(raw).hexdigest() != claims["manifest_sha256"]):
            raise Denied("RESOURCE_MANIFEST_CHANGED")
        manifest = parse_manifest(bytes(raw))
        expected, total = _manifest(manifest, now)
        if manifest["application_schema"] != application_schema:
            raise Denied("RESOURCE_ARCHIVE_INCOMPATIBLE")
        if members.keys() != expected.keys() or any(
            len(members[name]) != size or hashlib.sha256(members[name]).hexdigest() != digest
            for name, (size, digest) in expected.items()
        ):
            raise Denied("RESOURCE_PAYLOAD_CHANGED")
        _stage(destination, manifest, members)
        return {"status": "RESTORE_STAGED", "restore_eligibility": "NOT_EVALUATED", "procedure": procedure,
                "archive": {"captured_utc": manifest["captured_utc"], "ciphertext_sha256": claims["ciphertext_sha256"],
                            "entries": len(manifest["entries"]), "bytes": total}}
    finally:
        if plaintext is not None:
            wipe(plaintext)
