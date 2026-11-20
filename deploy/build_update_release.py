"""Build an offline, publisher-signed update candidate from prepared artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

from nacl.signing import SigningKey

if __package__:
    from .artifact import ArtifactError, canonical, file_at
    from .update_release import MAX_UPDATER_SIZE, PLATFORM, verify_candidate, version
else:
    from artifact import ArtifactError, canonical, file_at
    from update_release import MAX_UPDATER_SIZE, PLATFORM, verify_candidate, version


def signer_from_file(path):
    with file_at(path.parent, path.name) as (fd, info):
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_size != 32:
            raise ArtifactError("UPDATE_SIGNING_KEY_INVALID")
        seed = os.read(fd, 33)
        if len(seed) != 32:
            raise ArtifactError("UPDATE_SIGNING_KEY_INVALID")
        return SigningKey(seed)


def copy_updater(source, destination):
    with file_at(source.parent, source.name) as (fd, info):
        if not 1 <= info.st_size <= MAX_UPDATER_SIZE:
            raise ArtifactError("UPDATE_UPDATER_INVALID")
        size = 0
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as source_file, destination.open("xb") as output:
            while chunk := source_file.read(min(info.st_size - size + 1, 1024 * 1024)):
                size += len(chunk)
                if size > info.st_size:
                    raise ArtifactError("UPDATE_UPDATER_CHANGED")
                digest.update(chunk)
                output.write(chunk)
            if size != info.st_size:
                raise ArtifactError("UPDATE_UPDATER_CHANGED")
        return {"size": size, "sha256": digest.hexdigest()}


def build_release(output, updater, signer, *, release_version, installed, bootstrap, minimum_release,
                  schema, schema_to, vault_format, images):
    version(release_version)
    if os.path.lexists(output):
        raise ArtifactError("UPDATE_OUTPUT_EXISTS")
    work = Path(tempfile.mkdtemp(prefix=".hostorbit-release-", dir=output.parent))
    try:
        filename = f"hostorbit-updater-{PLATFORM}-{release_version}.tar.zst"
        archive = copy_updater(updater, work / filename)
        key = bytes(signer.verify_key)
        release = {
            "v": 1, "version": release_version, "platform": PLATFORM,
            "min_bootstrap_version": bootstrap, "min_allowed_release": minimum_release,
            "schema_compatibility": {"from": schema, "to": schema_to}, "vault_format": vault_format,
            "signing_key_id": hashlib.sha256(key).hexdigest(), "images": images, "updater": archive,
        }
        manifest = canonical(release)
        (work / "release.json").write_bytes(manifest)
        (work / "release.sig").write_bytes(signer.sign(manifest).signature)
        report = verify_candidate(work, key, installed=installed, bootstrap=bootstrap, schema=schema,
                                  vault_format=vault_format, minimum_release=minimum_release)
        work.rename(output)
        return report
    finally:
        if work.exists():
            shutil.rmtree(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--updater", type=Path, required=True, help="Prepared updater tar.zst archive")
    parser.add_argument("--signing-key", type=Path, required=True, help="Private file containing the offline 32-byte Ed25519 seed")
    parser.add_argument("--version", required=True)
    parser.add_argument("--installed", required=True, help="Current release version for the compatibility check")
    parser.add_argument("--min-bootstrap", required=True)
    parser.add_argument("--min-release", required=True)
    parser.add_argument("--schema-from", type=int, required=True)
    parser.add_argument("--schema-to", type=int, required=True)
    parser.add_argument("--vault-format", type=int, required=True)
    for name in ("web", "api", "worker"):
        parser.add_argument(f"--{name}-digest", required=True)
    args = parser.parse_args()
    try:
        report = build_release(
            args.output, args.updater, signer_from_file(args.signing_key), release_version=args.version,
            installed=args.installed, bootstrap=args.min_bootstrap, minimum_release=args.min_release,
            schema=args.schema_from, schema_to=args.schema_to, vault_format=args.vault_format,
            images={name: getattr(args, f"{name}_digest") for name in ("web", "api", "worker")},
        )
    except (ArtifactError, OSError) as error:
        print(f"HostOrbit: {error if isinstance(error, ArtifactError) else 'UPDATE_BUILD_IO_FAILED'}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
