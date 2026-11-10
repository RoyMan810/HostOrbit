"""Small stdlib-only verifier used before any bundle code or wheel is executed."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile


FIXED_FILES = {
    "deploy/artifact.py", "deploy/installer.py", "deploy/Controller.Dockerfile",
    "deploy/sysusers.d/hostorbit.conf", "requirements-install.txt", "sbom.cdx.json",
    *("deploy/systemd/" + name for name in (
        "hostorbit-broker.service", "hostorbit-broker.socket",
        "hostorbit-supervisor.service", "hostorbit-supervisor.socket")),
}
IMAGE = r"docker\.io/library/python@sha256:[0-9a-f]{64}"
MAX_FILE = 64 * 1024 * 1024
# Official v1.3.2 linux/amd64 binary from the independently checksum-pinned
# release archive (cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10).
AGE_FILE = "tools/age"
AGE_SHA256 = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c"
AGE_VERSION = "v1.3.2"


class ArtifactError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError("DUPLICATE_MANIFEST_FIELD")
        result[key] = value
    return result


def parse(data):
    try:
        value = json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: None)
        if canonical(value) != data:
            raise ValueError
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ArtifactError("MANIFEST_ENCODING_INVALID") from None


@contextmanager
def file_at(root, relative):
    """Walk with directory descriptors; never follow a replaced parent symlink."""
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(p in (".", "..") for p in parts):
        raise ArtifactError("ARTIFACT_PATH_INVALID")
    descriptors = []
    try:
        descriptors.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in parts[:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
        descriptors.append(os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1]))
        info = os.fstat(descriptors[-1])
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ArtifactError("ARTIFACT_FILE_INVALID")
        yield descriptors[-1], info
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_at(root, relative, maximum):
    with file_at(root, relative) as (fd, info):
        if info.st_size > maximum:
            raise ArtifactError("ARTIFACT_TOO_LARGE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ArtifactError("ARTIFACT_TOO_LARGE")
        return data


def trusted_key(path, *, owner=0):
    path = Path(path).absolute()
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                or (stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ArtifactError("TRUST_KEY_PARENT_PERMISSIONS")
    with file_at(path.parent, path.name) as (fd, info):
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o022 or info.st_size != 32:
            raise ArtifactError("TRUST_KEY_PERMISSIONS")
        return os.read(fd, 33)


def verify_signature(data, signature, key):
    if len(signature) != 64 or len(key) != 32:
        raise ArtifactError("ARTIFACT_SIGNATURE_INVALID")
    with tempfile.TemporaryDirectory(prefix="hostorbit-verify-") as directory:
        root = Path(directory)
        # RFC 8410 SubjectPublicKeyInfo for an Ed25519 public key.
        (root / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        (root / "manifest").write_bytes(data)
        (root / "signature").write_bytes(signature)
        result = subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
            "-inkey", str(root / "key.der"), "-rawin", "-in", str(root / "manifest"),
            "-sigfile", str(root / "signature"),
        ], capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null"})
        if result.returncode:
            raise ArtifactError("ARTIFACT_SIGNATURE_INVALID")


def manifest(bundle, key, *, allow_development=False):
    data = read_at(bundle, "manifest.json", 65536)
    signature = read_at(bundle, "manifest.sig", 64)
    verify_signature(data, signature, key)
    value = parse(data)
    expected = {"v", "application", "version", "channel", "source_commit", "python_image", "files",
                "platform", "python", "sqlite_schema", "remote_mutation_enabled", "signing_key_sha256"}
    if (not isinstance(value, dict) or value.keys() != expected or type(value["v"]) is not int or value["v"] != 1
            or value["application"] != "HostOrbit" or value["platform"] != "ubuntu-24.04-amd64"
            or value["python"] not in ("3.13", "3.15") or type(value["sqlite_schema"]) is not int or value["sqlite_schema"] != 2
            or value["remote_mutation_enabled"] is not False or value["channel"] != "development"
            or not allow_development or not isinstance(value["version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.dev[0-9]+", value["version"])
            or re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is None
            or re.fullmatch(IMAGE, value["python_image"]) is None
            or value["signing_key_sha256"] != hashlib.sha256(key).hexdigest()):
        raise ArtifactError("BUNDLE_CONTRACT_UNSUPPORTED")
    files = value["files"]
    if not isinstance(files, list) or not 10 <= len(files) <= 100:
        raise ArtifactError("MANIFEST_FILES_INVALID")
    paths, total = set(), 0
    for item in files:
        if not isinstance(item, dict) or item.keys() != {"path", "sha256", "size"}:
            raise ArtifactError("MANIFEST_FILES_INVALID")
        path = item["path"]
        if (not isinstance(path, str) or path in paths or (path not in FIXED_FILES and path != AGE_FILE and
                re.fullmatch(r"wheelhouse/[A-Za-z0-9_.+-]+\.whl", path) is None)
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE
                or not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
            raise ArtifactError("MANIFEST_FILES_INVALID")
        if path == AGE_FILE and item["sha256"] != AGE_SHA256:
            raise ArtifactError("AGE_TOOL_DIGEST_UNSUPPORTED")
        paths.add(path)
        total += item["size"]
    if not FIXED_FILES.issubset(paths) or total > 384 * 1024 * 1024:
        raise ArtifactError("MANIFEST_FILES_INVALID")
    app = [p for p in paths if p.startswith("wheelhouse/hostorbit-")]
    if len(app) != 1 or app[0] != f"wheelhouse/hostorbit-{value['version']}-py3-none-any.whl":
        raise ArtifactError("APPLICATION_WHEEL_INVALID")
    return value, data, signature


def snapshot(bundle, destination, key, *, allow_development=False):
    """Copy the authenticated bytes to a private directory before executing any."""
    value, data, signature = manifest(bundle, key, allow_development=allow_development)
    destination = Path(destination)
    destination.mkdir(mode=0o700, exist_ok=False)
    for item in value["files"]:
        content = read_at(bundle, item["path"], item["size"])
        if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ArtifactError("ARTIFACT_DIGEST_MISMATCH")
        path = destination / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o644)
    (destination / "manifest.json").write_bytes(data)
    (destination / "manifest.sig").write_bytes(signature)
    return value, hashlib.sha256(data).hexdigest()
