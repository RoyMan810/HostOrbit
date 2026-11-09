"""Offline integrity checks for one stopped Docker named-volume archive format."""

import base64
import hashlib
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..errors import Denied
from .archive_stream import AGE_PATH, AGE_SHA256, parse_manifest, recipient
from .protocol import SHA256, ULID, canonical, fields, integer, text
from .rescue import ciphertext_stream, decrypt, offline_profile, wipe
from .rescue_payload import MAX_PAYLOAD, unpack


_MANIFEST_PATH = "resource/manifest.json"
_MAX_MANIFEST_SIZE = 4 * 1024 * 1024
_MAX_ENTRIES = 8192
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
_METADATA = ("uid", "gid", "mode")


def _metadata(value):
    integer(value["uid"], 0, 2**31 - 1)
    integer(value["gid"], 0, 2**31 - 1)
    integer(value["mode"], 0, 0o777)


def _manifest(value, now):
    try:
        fields(value, ("v", "resource_type", "application_schema", "source_host", "source_volume",
                       "captured_utc", "quiescence", "overwrite", "root", "entries"))
        integer(value["v"], 1, 1)
        if (value["resource_type"] != "docker.named-volume" or value["quiescence"] != "STOPPED"
                or value["overwrite"] != "new_empty_target_only"):
            raise Denied("RESOURCE_MANIFEST_INVALID")
        text(value["application_schema"], _NAME)
        text(value["source_host"], ULID)
        text(value["source_volume"], _NAME)
        integer(value["captured_utc"], 0, now)
        _metadata(fields(value["root"], _METADATA))
        entries = value["entries"]
        if not isinstance(entries, list) or len(entries) > _MAX_ENTRIES:
            raise Denied("RESOURCE_MANIFEST_INVALID")
        layout, payload, total = {}, {}, 0
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("kind") not in ("file", "directory"):
                raise Denied("RESOURCE_MANIFEST_INVALID")
            file = entry["kind"] == "file"
            fields(entry, ("kind", "path", *_METADATA, *(("size", "sha256") if file else ())))
            _metadata(entry)
            path = text(entry["path"], r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
            if len(path) > 240 or path in layout or any(part in (".", "..") for part in path.split("/")):
                raise Denied("RESOURCE_MANIFEST_INVALID")
            layout[path] = entry["kind"]
            if file:
                size = integer(entry["size"], 0, MAX_PAYLOAD - total)
                digest = text(entry["sha256"], SHA256)
                if size:
                    payload["volume/" + path] = (size, digest)
                elif digest != _EMPTY_SHA256:
                    raise Denied("RESOURCE_MANIFEST_INVALID")
                total += size
        for path in layout:
            parent, _, _ = path.rpartition("/")
            if parent and layout.get(parent) != "directory":
                raise Denied("RESOURCE_MANIFEST_INVALID")
        return payload, total
    except Denied:
        raise Denied("RESOURCE_MANIFEST_INVALID") from None


def _claims(envelope, trusted_key):
    try:
        fields(envelope, ("claims", "signature"))
        claims = fields(envelope["claims"], ("v", "type", "application_schema", "manifest_sha256", "recipient", "ciphertext_sha256",
                                             "ciphertext_size", "age_sha256", "signing_key_sha256"))
        integer(claims["v"], 1, 1)
        if (claims["type"] != "hostorbit.resource-backup" or claims["age_sha256"] != AGE_SHA256
                or claims["signing_key_sha256"] != hashlib.sha256(trusted_key).hexdigest()):
            raise Denied("RESOURCE_PROVENANCE_INVALID")
        text(claims["ciphertext_sha256"], SHA256)
        text(claims["manifest_sha256"], SHA256)
        text(claims["application_schema"], _NAME)
        integer(claims["ciphertext_size"], 200, MAX_PAYLOAD)
        recipient(claims["recipient"])
        VerifyKey(trusted_key).verify(canonical(claims), base64.b64decode(envelope["signature"], validate=True))
        return claims
    except (Denied, BadSignatureError, ValueError, TypeError, RecursionError):
        raise Denied("RESOURCE_PROVENANCE_INVALID") from None


def _check_ciphertext(stream, claims):
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = claims["ciphertext_size"]
    while remaining:
        chunk = stream.read(min(65536, remaining))
        if not chunk:
            raise Denied("RESOURCE_CIPHERTEXT_CHANGED")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1) or digest.hexdigest() != claims["ciphertext_sha256"]:
        raise Denied("RESOURCE_CIPHERTEXT_CHANGED")
    stream.seek(0)


def verify_archive(ciphertext, envelope, trusted_key, identity, *, application_schema, now=None,
                   age_path=AGE_PATH, tool_owner=0):
    """Verify bytes and schema without touching a target or authorizing restore."""
    offline_profile()
    now = int(time.time()) if now is None else now
    claims = _claims(envelope, trusted_key)
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
        return {
            "status": "INTEGRITY_VERIFIED", "restore_eligibility": "NOT_EVALUATED",
            "resource_type": manifest["resource_type"], "application_schema": application_schema,
            "captured_utc": manifest["captured_utc"], "source_host": manifest["source_host"],
            "source_volume": manifest["source_volume"], "ciphertext_sha256": claims["ciphertext_sha256"],
            "entries": len(manifest["entries"]), "bytes": total,
        }
    finally:
        if plaintext is not None:
            wipe(plaintext)
