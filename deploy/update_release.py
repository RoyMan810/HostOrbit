"""Verify a publisher-signed HostOrbit update candidate without activating it."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

if __package__:
    from .artifact import ArtifactError, file_at, parse, read_at, trusted_key, verify_signature
else:
    from artifact import ArtifactError, file_at, parse, read_at, trusted_key, verify_signature


DIGEST = r"[0-9a-f]{64}"
VERSION = r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})"
PLATFORM = "linux-amd64"
MAX_UPDATER_SIZE = 128 * 1024 * 1024


def version(value):
    if not isinstance(value, str) or re.fullmatch(VERSION, value) is None:
        raise ArtifactError("UPDATE_VERSION_INVALID")
    return tuple(map(int, value.split(".")))


def verify_candidate(directory, key, *, installed, bootstrap, schema, vault_format, minimum_release):
    data = read_at(directory, "release.json", 65536)
    verify_signature(data, read_at(directory, "release.sig", 64), key)
    release = parse(data)
    expected = {"v", "version", "platform", "min_bootstrap_version", "min_allowed_release",
                "schema_compatibility", "vault_format", "signing_key_id", "images", "updater"}
    if (not isinstance(release, dict) or release.keys() != expected or type(release["v"]) is not int
            or release["v"] != 1 or release["platform"] != PLATFORM
            or release["signing_key_id"] != hashlib.sha256(key).hexdigest()):
        raise ArtifactError("UPDATE_RELEASE_INVALID")
    candidate = version(release["version"])
    if (candidate <= version(installed) or candidate < version(minimum_release)
            or candidate < version(release["min_allowed_release"])):
        raise ArtifactError("UPDATE_RELEASE_TOO_OLD")
    if version(bootstrap) < version(release["min_bootstrap_version"]):
        raise ArtifactError("UPDATE_BOOTSTRAP_INCOMPATIBLE")
    compatibility = release["schema_compatibility"]
    if (not isinstance(compatibility, dict) or compatibility.keys() != {"from", "to"}
            or type(compatibility["from"]) is not int or type(compatibility["to"]) is not int
            or type(release["vault_format"]) is not int or release["vault_format"] < 1
            or release["vault_format"] != vault_format
            or not 1 <= schema <= 2**31 - 2 or compatibility["from"] != schema
            or compatibility["to"] not in (schema, schema + 1)):
        raise ArtifactError("UPDATE_DATA_INCOMPATIBLE")
    images = release["images"]
    if (not isinstance(images, dict) or images.keys() != {"web", "api", "worker"}
            or any(not isinstance(digest, str) or re.fullmatch(r"sha256:" + DIGEST, digest) is None
                   for digest in images.values())):
        raise ArtifactError("UPDATE_IMAGE_DIGEST_INVALID")
    updater = release["updater"]
    if (not isinstance(updater, dict) or updater.keys() != {"sha256", "size"}
            or type(updater["size"]) is not int or not 1 <= updater["size"] <= MAX_UPDATER_SIZE
            or not isinstance(updater["sha256"], str) or re.fullmatch(DIGEST, updater["sha256"]) is None):
        raise ArtifactError("UPDATE_UPDATER_INVALID")
    filename = f"hostorbit-updater-{PLATFORM}-{release['version']}.tar.zst"
    with file_at(directory, filename) as (fd, info):
        if info.st_size != updater["size"]:
            raise ArtifactError("UPDATE_UPDATER_DIGEST_MISMATCH")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            remaining = updater["size"]
            digest = hashlib.sha256()
            while remaining and (chunk := stream.read(min(remaining, 1024 * 1024))):
                remaining -= len(chunk)
                digest.update(chunk)
            if remaining or stream.read(1) or digest.hexdigest() != updater["sha256"]:
                raise ArtifactError("UPDATE_UPDATER_DIGEST_MISMATCH")
    return {"status": "CANDIDATE_VERIFIED", "version": release["version"],
            "release_sha256": hashlib.sha256(data).hexdigest(), "schema_to": compatibility["to"],
            "images": images, "applied": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trust-key", required=True, type=Path)
    parser.add_argument("--installed", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--minimum-release", required=True)
    parser.add_argument("--schema", required=True, type=int)
    parser.add_argument("--vault-format", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        report = verify_candidate(args.directory, trusted_key(args.trust_key), installed=args.installed,
                                  bootstrap=args.bootstrap, schema=args.schema, vault_format=args.vault_format,
                                  minimum_release=args.minimum_release)
    except (ArtifactError, OSError) as exc:
        print(f"HostOrbit: {exc if isinstance(exc, ArtifactError) else 'UPDATE_RELEASE_UNREADABLE'}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
