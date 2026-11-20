"""Rehearse a verified release and A/B switching in a disposable directory."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from deploy.artifact import ArtifactError, read_at, trusted_key
from deploy.build_update_release import copy_updater
from deploy.update_release import PLATFORM, verify_candidate
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.migration_review import verify_rehearsal
from vpn_orbit.runtime.storage import directory_sync


def stage_candidate(source, slot, key, compatibility):
    slot.mkdir(mode=0o700)
    for name, limit in (("release.json", 65536), ("release.sig", 64)):
        (slot / name).write_bytes(read_at(source, name, limit))
    metadata = verify_candidate(source, key, **compatibility)
    filename = f"vpn-orbit-updater-{PLATFORM}-{metadata['version']}.tar.zst"
    copy_updater(source / filename, slot / filename)
    staged = verify_candidate(slot, key, **compatibility)
    if staged != metadata:
        raise ArtifactError("UPDATE_CANDIDATE_CHANGED")
    return staged


def select_slot(root, slot):
    if slot not in ("A", "B") or not (root / slot).is_dir():
        raise ArtifactError("UPDATE_SLOT_INVALID")
    next_link = root / ".active-next"
    next_link.symlink_to(slot, target_is_directory=True)
    try:
        next_link.replace(root / "active")
        directory_sync(root)
    finally:
        if next_link.is_symlink():
            next_link.unlink()


def rehearse_update(source, key, *, installed, bootstrap, schema, vault_format, minimum_release,
                    migration=None):
    compatibility = dict(installed=installed, bootstrap=bootstrap, schema=schema, vault_format=vault_format,
                         minimum_release=minimum_release)
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-update-rehearsal-") as directory:
        root = Path(directory)
        current = root / "A"
        current.mkdir(mode=0o700)
        (current / "stand-in").write_text(installed, encoding="utf-8")
        select_slot(root, "A")
        candidate = stage_candidate(Path(source), root / "B", key, compatibility)

        if candidate["schema_to"] != schema and migration is None:
            raise ArtifactError("UPDATE_MIGRATION_REHEARSAL_REQUIRED")
        if migration is not None:
            review = verify_rehearsal(migration)
            if (review["schema_before"], review["schema_after"]) != (schema, candidate["schema_to"]):
                raise ArtifactError("UPDATE_MIGRATION_REHEARSAL_MISMATCH")

        select_slot(root, "B")
        # The candidate is assessed from its private slot after the switch.
        # A health failure exercises rollback without executing candidate code.
        verified = False
        try:
            if os.readlink(root / "active") == "B":
                verified = verify_candidate(root / "B", key, **compatibility) == candidate
        except (ArtifactError, OSError):
            pass
        finally:
            select_slot(root, "A")

        if os.readlink(root / "active") != "A" or (root / "active" / "stand-in").read_text() != installed:
            raise ArtifactError("UPDATE_REHEARSAL_ROLLBACK_FAILED")
        return {"status": "UPDATE_REHEARSAL_PASSED" if verified else "UPDATE_REHEARSAL_ROLLED_BACK",
                "release_sha256": candidate["release_sha256"],
                "version": candidate["version"], "candidate_verified_after_switch": verified,
                "rollback_verified": True, "migration_verified": migration is not None, "applied": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--installed", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--minimum-release", required=True)
    parser.add_argument("--schema", type=int, required=True)
    parser.add_argument("--vault-format", type=int, required=True)
    parser.add_argument("--migration-review", type=Path)
    args = parser.parse_args(argv)
    try:
        report = rehearse_update(args.directory, trusted_key(args.trust_key, owner=os.geteuid()),
                                 installed=args.installed, bootstrap=args.bootstrap,
                                 minimum_release=args.minimum_release, schema=args.schema,
                                 vault_format=args.vault_format, migration=args.migration_review)
    except (ArtifactError, Denied, OSError, ValueError) as error:
        if isinstance(error, ArtifactError):
            code = str(error)
        elif isinstance(error, Denied):
            code = error.code
        else:
            code = "UPDATE_REHEARSAL_UNAVAILABLE"
        print(f"VPN-Orbit: {code}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["candidate_verified_after_switch"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
