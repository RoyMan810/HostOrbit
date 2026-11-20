"""Bind a signed release, SQLite rehearsal and verified backup copy to one review."""

import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time

from deploy.artifact import ArtifactError, trusted_key
from deploy.update_release import verify_candidate
from hostorbit.database import DataAccess, Store
from hostorbit.errors import Denied
from hostorbit.migrations import _source_digest, _verify
from hostorbit.runtime.authority import verify_host_time
from hostorbit.runtime.cli import configuration
from hostorbit.runtime.ipc import Client
from hostorbit.runtime.migration_backup import check_publication
from hostorbit.runtime.migration_review import verify_rehearsal
from hostorbit.runtime.protocol import checksum
from hostorbit.runtime.storage import protected_bytes


def verify_current_source(config, schema, review_digest):
    store = Store(config["database"], access=DataAccess(config["app_uid"], config.get("app_gid")))
    deadline = time.monotonic() + 30

    def expired():
        return int(time.monotonic() >= deadline)

    with store.connect(readonly=True) as db:
        db.execute("BEGIN")
        db.set_progress_handler(expired, 1000)
        try:
            _verify(db, schema)
            sequence = db.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0]
            current_digest, _ = _source_digest(db, sequence, schema)
        except sqlite3.Error:
            if expired():
                raise Denied("MIGRATION_SOURCE_REVIEW_TIMEOUT") from None
            raise
        if expired():
            raise Denied("MIGRATION_SOURCE_REVIEW_TIMEOUT")
        if not secrets.compare_digest(current_digest, review_digest):
            raise Denied("MIGRATION_REHEARSAL_SOURCE_CHANGED")


def prepare_migration(config, release, key, gate, *, installed, bootstrap, schema, vault_format,
                      minimum_release, review, snapshot_id, downloaded_copy, owner=0):
    if os.geteuid() != owner:
        raise Denied("LOCAL_ROOT_REQUIRED")
    candidate = verify_candidate(release, key, installed=installed, bootstrap=bootstrap,
                                 schema=schema, vault_format=vault_format, minimum_release=minimum_release)
    if candidate["schema_to"] != schema + 1:
        raise Denied("MIGRATION_REQUIRED_RELEASE_EXPECTED")
    rehearsal = verify_rehearsal(review)
    if (rehearsal["schema_before"], rehearsal["schema_after"]) != (schema, candidate["schema_to"]):
        raise Denied("MIGRATION_RELEASE_REHEARSAL_MISMATCH")
    backup = check_publication(config, snapshot_id, downloaded_copy=downloaded_copy, owner=owner)
    if (backup["status"] != "FRESH_BACKUP_COPY_VERIFIED" or backup["snapshot_id"] != snapshot_id
            or backup["source_schema"] != schema):
        raise Denied("MIGRATION_BACKUP_COPY_REQUIRED")
    verify_current_source(config, schema, rehearsal["source_rows_sha256"])
    verify_key = protected_bytes(config["public_verify_key"], owner=owner, maximum=32)
    health = verify_host_time(gate.call("time.health", {}), verify_key)
    if (health.get("gate_state") != "NORMAL" or health.get("state") not in ("FRESH", "HOLDOVER")
            or health.get("authority_id") != backup["source_instance"]):
        raise Denied("MIGRATION_SUPERVISOR_UNAVAILABLE")

    plan = {
        "v": 1, "kind": "application_migration", "release_sha256": candidate["release_sha256"],
        "release_version": candidate["version"], "schema_before": schema, "schema_after": candidate["schema_to"],
        "source_rows_sha256": rehearsal["source_rows_sha256"], "source_instance": backup["source_instance"],
        "snapshot_id": snapshot_id, "backup_target_id": backup["target_id"],
        "backup_marker_sha256": backup["marker_sha256"], "gate_epoch": health["gate_epoch"],
        "time_generation": health["generation"],
    }
    return {"status": "MIGRATION_INPUTS_VERIFIED", "plan": plan, "plan_sha256": checksum(plan),
            "backup_maximum_age_seconds": backup["maximum_age_seconds"], "backup_gate": backup["backup_gate"],
            "restore_verified": backup["restore_verified"], "failure_domain_verified": backup["failure_domain_verified"],
            "live_apply": "BLOCKED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--installed", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--minimum-release", required=True)
    parser.add_argument("--schema", type=int, required=True)
    parser.add_argument("--vault-format", type=int, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--downloaded-copy", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Denied("LOCAL_ROOT_REQUIRED")
        config = configuration(Path("/etc/hostorbit/runtime.json"))
        report = prepare_migration(
            config, args.release, trusted_key(args.trust_key), Client(config["gate_socket"], server_uids={0}),
            installed=args.installed, bootstrap=args.bootstrap, schema=args.schema, vault_format=args.vault_format,
            minimum_release=args.minimum_release, review=args.review, snapshot_id=args.snapshot_id,
            downloaded_copy=args.downloaded_copy,
        )
    except (ArtifactError, Denied, OSError, ValueError, RuntimeError, sqlite3.Error, KeyError, TypeError) as error:
        if isinstance(error, ArtifactError):
            code = str(error)
        elif isinstance(error, Denied):
            code = error.code
        else:
            code = "MIGRATION_INPUTS_UNAVAILABLE"
        print(f"HostOrbit: {code}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
