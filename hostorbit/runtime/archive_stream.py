"""One-way Broker → age encryption. Portable DEK bytes never enter a file/RPC.

Root sends bounded whitelisted Controller members on stdin. Broker appends its
private authenticated pin and an in-memory keyset directly to age's input pipe.
"""

import base64
from contextlib import closing, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import subprocess
import tarfile

from nacl.exceptions import CryptoError

from ..errors import Denied
from .pins import _metadata, _private_directory
from .protocol import SHA256, ULID, canonical, checksum, decode, fields, integer, text, unique_object
from .storage import protected_bytes


AGE_SHA256 = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c"
AGE_PATH = Path("/opt/hostorbit/tools/age")
CONTROLLER_FILES = frozenset({"app.sqlite3", "gate.sqlite3", "runtime.json", "targets.json", "gate.pub",
                              "installation.json", "release-manifest.json", "release.sig", "release.pub",
                              "requirements-install.txt", "sbom.cdx.json", "compose.json"})
MAX_FILE = 512 * 1024 * 1024


def recipient(value):
    # age itself also checks Bech32 checksum/encoding before encrypting. Only
    # native X25519 recipients are accepted, never plugins/SSH/passphrases.
    return text(value, r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", "BACKUP_RECIPIENT_INVALID")


@contextmanager
def private_stream(path, owner):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= MAX_FILE):
            raise Denied("ARCHIVE_FILE_INVALID")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            yield stream, info.st_size
    finally:
        os.close(fd)


def file_record(path, name, owner):
    digest = hashlib.sha256()
    with private_stream(path, owner) as (stream, size):
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return {"path": name, "size": size, "sha256": digest.hexdigest()}


def parse_manifest(raw):
    try:
        if not 0 < len(raw) <= 32 * 1024 * 1024:
            raise ValueError()
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if canonical(value) != raw:
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied("ARCHIVE_MANIFEST_INVALID") from None


def validate_source(value, snapshot_id):
    fields(value, ("v", "type", "snapshot_id", "source_instance", "gate_epoch", "schema", "audit_head", "audit_sequence",
                   "boot_id", "monotonic_ns", "captured_utc", "time_trusted", "source_commit", "pin_sha256", "files"))
    if (type(value["v"]) is not int or value["v"] != 1 or value["type"] != "controller.snapshot"
            or value["snapshot_id"] != snapshot_id or value["time_trusted"] is not False):
        raise Denied("ARCHIVE_MANIFEST_INVALID")
    text(snapshot_id, ULID)
    text(value["source_instance"], ULID)
    text(value["audit_head"], SHA256)
    text(value["pin_sha256"], SHA256)
    text(value["source_commit"], r"[0-9a-f]{40}")
    text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    for name in ("gate_epoch", "audit_sequence", "monotonic_ns", "captured_utc"):
        integer(value[name], 0, 2**63 - 1)
    integer(value["schema"], 1, 2)
    if not isinstance(value["files"], list) or len(value["files"]) != len(CONTROLLER_FILES):
        raise Denied("ARCHIVE_MANIFEST_INVALID")
    names = set()
    for item in value["files"]:
        fields(item, ("path", "size", "sha256"))
        if not isinstance(item["path"], str) or item["path"] not in CONTROLLER_FILES or item["path"] in names:
            raise Denied("ARCHIVE_MANIFEST_INVALID")
        names.add(item["path"])
        integer(item["size"], 1, MAX_FILE)
        text(item["sha256"], SHA256)
    return value


def validated_pin(vault, broker_directory, snapshot_id, expected_digest):
    directory = Path(broker_directory) / "snapshot-pins" / text(snapshot_id, ULID)
    for path in (Path(broker_directory), directory.parent, directory, directory / "objects"):
        _private_directory(path)
    raw = protected_bytes(directory / "pin.json", owner=os.geteuid(), maximum=32 * 1024 * 1024, exact_mode=0o600)
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise Denied("ARCHIVE_PIN_CHANGED")
    pin = parse_manifest(raw)
    fields(pin, ("v", "type", "snapshot_id", "key_generations", "key_fingerprints", "references", "files"))
    if (type(pin["v"]) is not int or pin["v"] != 1 or pin["type"] != "vault.pin" or pin["snapshot_id"] != snapshot_id
            or pin["key_generations"] != [1] or pin["key_fingerprints"] != {"1": hashlib.sha256(bytes(vault._aead)).hexdigest()}):
        raise Denied("ARCHIVE_KEYSET_UNAVAILABLE")
    if not isinstance(pin["references"], list) or len(pin["references"]) > 65536 or not isinstance(pin["files"], list):
        raise Denied("ARCHIVE_MANIFEST_INVALID")
    expected = {"vault.sqlite3", "receipts.sqlite3"}
    for reference in pin["references"]:
        fields(reference, ("ref", "state", "object_digest", "metadata_sha256", "key_generation"))
        text(reference["object_digest"], SHA256)
        expected.add("objects/" + reference["object_digest"])
    if len(pin["files"]) != len(expected):
        raise Denied("ARCHIVE_PIN_INCOMPLETE")
    seen = set()
    for item in pin["files"]:
        fields(item, ("path", "size", "sha256"))
        name = item["path"]
        if not isinstance(name, str) or name not in expected or name in seen:
            raise Denied("ARCHIVE_PIN_INCOMPLETE")
        seen.add(name)
        if file_record(directory / name, name, os.geteuid()) != item:
            raise Denied("ARCHIVE_PIN_CHANGED")
    references = []
    with closing(sqlite3.connect((directory / "vault.sqlite3").as_uri() + "?mode=ro", uri=True, autocommit=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        for row in db.execute("SELECT * FROM secrets ORDER BY ref"):
            metadata = _metadata(row)
            digest = text(row["object_digest"], SHA256)
            ciphertext = protected_bytes(directory / "objects" / digest, owner=os.geteuid(), maximum=9000, exact_mode=0o600)
            try:
                plaintext = vault._aead.decrypt(ciphertext, canonical(metadata))
            except CryptoError:
                raise Denied("ARCHIVE_PIN_CHANGED") from None
            del plaintext
            references.append({"ref": row["ref"], "state": row["state"], "object_digest": digest,
                               "metadata_sha256": checksum(metadata), "key_generation": 1})
    if references != pin["references"]:
        raise Denied("ARCHIVE_PIN_INCOMPLETE")
    return directory, raw, pin


def trusted_age(path=AGE_PATH, *, owner=0):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                or (stat.S_IMODE(info.st_mode) & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise Denied("AGE_TOOL_PERMISSIONS")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o755 or not 0 < info.st_size < 64 * 1024 * 1024):
            raise Denied("AGE_TOOL_PERMISSIONS")
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != AGE_SHA256:
            raise Denied("AGE_TOOL_DIGEST_INVALID")
    finally:
        os.close(fd)
    return str(path)


class _Bounded:
    def __init__(self, stream, item):
        self.stream, self.left = stream, item["size"]
        self.digest, self.expected = hashlib.sha256(), item["sha256"]

    def read(self, size):
        data = self.stream.read(min(size, self.left))
        self.left -= len(data)
        self.digest.update(data)
        return data

    def verify(self):
        if self.left or self.digest.hexdigest() != self.expected:
            raise Denied("ARCHIVE_SOURCE_CHANGED")


def _member(tar, name, stream, size):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, 0o600, 0
    info.uid = info.gid = 0
    tar.addfile(info, stream)


def _exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise Denied("ARCHIVE_INPUT_TRUNCATED")
        result.extend(chunk)
    return bytes(result)


def seal(vault, broker_directory, snapshot_id, incoming, outgoing, *, age_path=AGE_PATH, age_owner=0):
    size, = struct.unpack("!I", _exact(incoming, 4))
    integer(size, 1, 16384)
    header = fields(decode(_exact(incoming, size)), ("v", "recipient", "manifest"))
    if type(header["v"]) is not int or header["v"] != 1:
        raise Denied("ARCHIVE_MANIFEST_INVALID")
    public_recipient = recipient(header["recipient"])
    manifest = validate_source(header["manifest"], snapshot_id)
    directory, raw_pin, pin = validated_pin(vault, broker_directory, snapshot_id, manifest["pin_sha256"])
    executable = trusted_age(age_path, owner=age_owner)
    # stdout is ciphertext only. No identity/passphrase/plugin arguments or
    # plaintext output path are accepted. stderr never carries raw input back.
    process = subprocess.Popen([executable, "--encrypt", "--recipient", public_recipient], stdin=subprocess.PIPE,
                               stdout=outgoing, stderr=subprocess.DEVNULL, start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"})
    try:
        with tarfile.open(mode="w|", fileobj=process.stdin, format=tarfile.USTAR_FORMAT) as tar:
            raw = canonical(manifest)
            _member(tar, "controller/manifest.json", io.BytesIO(raw), len(raw))
            for item in manifest["files"]:
                bounded = _Bounded(incoming, item)
                _member(tar, "controller/" + item["path"], bounded, item["size"])
                bounded.verify()
            if incoming.read(1):
                raise Denied("ARCHIVE_INPUT_TRAILING_DATA")
            _member(tar, "vault/pin.json", io.BytesIO(raw_pin), len(raw_pin))
            for item in pin["files"]:
                with private_stream(directory / item["path"], os.geteuid()) as (stream, length):
                    if length != item["size"]:
                        raise Denied("ARCHIVE_PIN_CHANGED")
                    bounded = _Bounded(stream, item)
                    _member(tar, "vault/" + item["path"], bounded, length)
                    bounded.verify()
            keyset = canonical({"v": 1, "type": "hostorbit.portable-keyset",
                                "generations": [{"version": 1, "key": base64.b64encode(bytes(vault._aead)).decode("ascii")}]})
            _member(tar, "vault/portable-keys.json", io.BytesIO(keyset), len(keyset))
            del keyset
        process.stdin.close()
        if process.wait(timeout=120) != 0:
            raise Denied("ARCHIVE_ENCRYPTION_FAILED")
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, 9)
        process.wait(timeout=2)
        raise
    finally:
        process.stdin.close()


def feed(directory, manifest, public_recipient, stream, *, owner=0):
    validate_source(manifest, manifest["snapshot_id"])
    header = canonical({"v": 1, "recipient": recipient(public_recipient), "manifest": manifest})
    integer(len(header), 1, 16384)
    stream.write(struct.pack("!I", len(header)) + header)
    for item in manifest["files"]:
        with private_stream(Path(directory) / item["path"], owner) as (source, length):
            if length != item["size"]:
                raise Denied("ARCHIVE_SOURCE_CHANGED")
            bounded = _Bounded(source, item)
            while data := bounded.read(65536):
                stream.write(data)
            bounded.verify()
    stream.flush()
