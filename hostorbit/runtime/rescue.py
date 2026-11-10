"""Offline Owner repackage. Owner identity stays on the isolated workstation.

The new target receives only a recipient-bound encrypted bundle. Its exact hash
must be carried separately by the Owner to a trusted local target console.
"""

from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import stat
import subprocess
import time

from ..errors import Denied
from .archive_stream import AGE_PATH, MAX_RECOVERY_HEADER, parse_manifest, recipient, trusted_age
from .controller_backup import verify_provenance
from .protocol import SHA256, ULID, canonical, checksum, fields, integer, text
from .rescue_payload import MAX_PAYLOAD, unpack, verify, write_tar
from .storage import directory_sync


ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
REQUEST_FIELDS = ("v", "type", "target_id", "recipient", "recipient_fingerprint", "challenge", "issued_at", "expires_at", "source_envelope_sha256")


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Linux PR_SET_DUMPABLE. This also prevents same-UID ptrace/proc memory reads.
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
        raise Denied("RESCUE_MEMORY_PROTECTION_UNAVAILABLE")


def offline_profile():
    """Deliberately narrow MVP profile; no unsafe CLI/env bypass.

    A namespace isolates this process from IP networks. Host hibernation must be
    unavailable at kernel level, not just a stopped userspace service.
    """
    harden()
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Denied("RESCUE_PLATFORM_UNSUPPORTED")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    version = release.get("VERSION_ID", "").strip('"')
    match = re.fullmatch(r"([0-9]{2,})\.(04|10)", version)
    if release.get("ID", "").strip('"') != "ubuntu" or match is None or tuple(map(int, match.groups())) < (24, 4):
        raise Denied("RESCUE_PLATFORM_UNSUPPORTED")
    if Path("/etc/hostorbit/runtime.json").exists():
        raise Denied("RESCUE_MUST_BE_OFFLINE_WORKSTATION")
    if len(Path("/proc/swaps").read_text().splitlines()) != 1:
        raise Denied("RESCUE_SWAP_ENABLED")
    if "disk" in Path("/sys/power/state").read_text().split():
        raise Denied("RESCUE_HIBERNATION_ENABLED")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]}
    if interfaces - {"lo"}:
        raise Denied("RESCUE_NETWORK_NOT_ISOLATED")
    available = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    if int(available["MemAvailable"].split()[0]) * 1024 < 6 * MAX_PAYLOAD:
        raise Denied("RESCUE_MEMORY_INSUFFICIENT")
    return {"profile": f"ubuntu-{version}-amd64-offline-v1", "swap": "OFF", "hibernation": "UNAVAILABLE", "ip_network": "ISOLATED"}


def validate_request(value, *, now=None):
    fields(value, REQUEST_FIELDS)
    now = int(time.time()) if now is None else now
    if type(value["v"]) is not int or value["v"] != 1 or value["type"] != "hostorbit.recovery-request":
        raise Denied("RESCUE_REQUEST_INVALID")
    text(value["target_id"], ULID)
    public = recipient(value["recipient"])
    if value["recipient_fingerprint"] != hashlib.sha256(public.encode("ascii")).hexdigest():
        raise Denied("RESCUE_RECIPIENT_CHANGED")
    text(value["challenge"], SHA256)
    text(value["source_envelope_sha256"], SHA256)
    integer(value["issued_at"], 0, 2**63 - 1)
    integer(value["expires_at"], value["issued_at"] + 1, value["issued_at"] + 900)
    if not value["issued_at"] <= now < value["expires_at"]:
        raise Denied("RESCUE_REQUEST_EXPIRED")
    return value


@contextmanager
def ciphertext_stream(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 200 <= info.st_size <= MAX_PAYLOAD:
            raise Denied("RESCUE_CIPHERTEXT_SIZE_UNSUPPORTED")
        with os.fdopen(fd, "rb", closefd=False) as source:
            yield source
    finally:
        os.close(fd)


def decrypt(source, identity, *, age_path=AGE_PATH, tool_owner=0):
    """Anonymous identity pipe; authenticated plaintext is retained only in RAM."""
    if not isinstance(identity, (bytes, bytearray)) or not 60 <= len(identity) <= 4096:
        raise Denied("RESCUE_IDENTITY_INVALID")
    executable = trusted_age(age_path, owner=tool_owner)
    read, write = os.pipe()
    process, plaintext = None, bytearray()
    try:
        os.write(write, identity)
        os.close(write)
        write = None
        process = subprocess.Popen([executable, "--decrypt", "--identity", f"/dev/fd/{read}"], stdin=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(read,),
                                   start_new_session=True, env=ENV)
        until = time.monotonic() + 180
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ)
            while True:
                left = until - time.monotonic()
                if left <= 0 or not poll.select(left):
                    raise Denied("RESCUE_DECRYPT_TIMEOUT")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                plaintext.extend(chunk)
                if len(plaintext) > MAX_PAYLOAD:
                    raise Denied("RESCUE_PAYLOAD_SIZE_UNSUPPORTED")
        if process.wait(timeout=max(0.1, until - time.monotonic())):
            raise Denied("RESCUE_DECRYPT_FAILED")
        return plaintext
    except BaseException:
        wipe(plaintext)
        raise
    finally:
        os.close(read)
        if write is not None:
            os.close(write)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, 9)
            process.wait(timeout=2)
            process.stdout.close()


def wipe(value):
    # Best effort only: Python/SQLite/age and the kernel can retain copies.
    block = bytes(65536)
    for offset in range(0, len(value), len(block)):
        length = min(len(block), len(value) - offset)
        value[offset:offset + length] = block[:length]


def _encrypted_output(path, public, members, *, age_path, tool_owner):
    executable = trusted_age(age_path, owner=tool_owner)
    path = Path(path).absolute()
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise Denied("RESCUE_OUTPUT_DIRECTORY_NOT_PRIVATE")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process, complete = None, False
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            process = subprocess.Popen([executable, "--encrypt", "--recipient", public], stdin=subprocess.PIPE,
                                       stdout=output, stderr=subprocess.DEVNULL, start_new_session=True, env=ENV)
            write_tar(process.stdin, members)
            process.stdin.close()
            if process.wait(timeout=120):
                raise Denied("RESCUE_ENCRYPT_FAILED")
            if os.fstat(fd).st_size > MAX_PAYLOAD:
                raise Denied("RESCUE_CIPHERTEXT_SIZE_UNSUPPORTED")
            output.flush()
            os.fsync(fd)
        directory_sync(path.parent)
        complete = True
    finally:
        os.close(fd)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, 9)
            process.wait(timeout=2)
            process.stdin.close()
        if not complete:
            path.unlink(missing_ok=True)
            directory_sync(path.parent)


def prepare_bundle(ciphertext, envelope, trusted_key, identity, request, output, *, age_path=AGE_PATH, tool_owner=0):
    profile = offline_profile()  # Before any access to the Owner identity by age.
    validate_request(request)
    if checksum(envelope) != request["source_envelope_sha256"]:
        raise Denied("RESCUE_SOURCE_CHANGED")
    plaintext = None
    try:
        with ciphertext_stream(ciphertext) as source:
            # Verify a held inode, then pass that very descriptor to age. An
            # in-place concurrent mutation also fails age authentication/hash.
            claims = verify_provenance(Path(f"/proc/self/fd/{source.fileno()}"), envelope, trusted_key)
            source.seek(0)
            plaintext = decrypt(source, identity, age_path=age_path, tool_owner=tool_owner)
            source.seek(0)
            verify_provenance(Path(f"/proc/self/fd/{source.fileno()}"), envelope, trusted_key)
        members = unpack(plaintext)
        summary = verify(members, claims, trusted_key)
        header = canonical({"v": 1, "type": "hostorbit.recovery-bundle", "request": request,
                            "source_envelope": envelope, "trusted_source_key": trusted_key.hex(), "summary": summary})
        if len(header) > MAX_RECOVERY_HEADER:
            raise Denied("RESCUE_HEADER_SIZE_UNSUPPORTED")
        members = {"recovery.json": memoryview(header), **members}
        validate_request(request)  # Expiry is about transport, never source age.
        _encrypted_output(output, request["recipient"], members, age_path=age_path, tool_owner=tool_owner)
        digest = hashlib.sha256()
        with Path(output).open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return {"status": "OWNER_REVIEW_REQUIRED", "bundle_sha256": digest.hexdigest(),
                "source_backup_hash": claims["ciphertext_sha256"], "source_envelope_sha256": checksum(envelope),
                "recipient_fingerprint": request["recipient_fingerprint"], "target_id": request["target_id"],
                "challenge": request["challenge"], "expires_at": request["expires_at"], "summary": summary,
                "profile": profile, "restore_verified": False, "backup_gate": "DENIED"}
    finally:
        if plaintext is not None:
            wipe(plaintext)
