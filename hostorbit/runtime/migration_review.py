"""Independently verify a completed private SQLite migration rehearsal."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

from ..database import Store
from ..errors import Denied
from ..migrations import _source_digest, _verify, _verify_copy_connection, migration_script
from .pins import _private_directory
from .protocol import canonical, decode
from .storage import protected_bytes


def verify_rehearsal(directory):
    directory = Path(directory).absolute()
    _private_directory(directory)
    report_path = directory / "rehearsal.json"
    if not stat.S_ISREG(report_path.lstat().st_mode):
        raise Denied("MIGRATION_REVIEW_REPORT_INVALID")
    report = decode(protected_bytes(report_path, owner=os.geteuid(), exact_mode=0o600))
    if not isinstance(report, dict):
        raise Denied("MIGRATION_REVIEW_REPORT_INVALID")
    before, after = report.get("schema_before"), report.get("schema_after")
    if (type(report.get("v")) is not int or report["v"] != 1 or report.get("status") != "REHEARSAL_PASSED"
            or report.get("applied_to_source") is not False or report.get("live_apply") != "BLOCKED"
            or type(before) is not int or type(after) is not int or before not in (1, 2, 3) or after != before + 1):
        raise Denied("MIGRATION_REVIEW_REPORT_INVALID")

    deadline = time.monotonic() + 30

    def expired():
        return int(time.monotonic() >= deadline)

    source = Store(directory / "source.sqlite3")
    migrated = Store(directory / "migrated.sqlite3")
    with _verify_copy_connection(source, before) as db:
        db.set_progress_handler(expired, 1000)
        db.execute("BEGIN")
        source_head = _verify(db, before)
        sequence = db.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0]
        source_rows, counts = _source_digest(db, sequence, before)
        snapshot = hashlib.sha256()
        with source.path.open("rb") as stream:
            while chunk := stream.read(256 * 1024):
                if expired():
                    raise Denied("MIGRATION_REVIEW_TIMEOUT")
                snapshot.update(chunk)

    with _verify_copy_connection(migrated, after) as db:
        db.set_progress_handler(expired, 1000)
        db.execute("BEGIN")
        migrated_head = _verify(db, after)
        migrated_rows, migrated_counts = _source_digest(db, sequence, before)
        events = db.execute("""SELECT seq,actor_id,event,target_id,outcome,details FROM audit
                               WHERE seq>? ORDER BY seq LIMIT 2""", (sequence,)).fetchall()
        expected_details = canonical({"from_schema": before, "to_schema": after, "rehearsal": True,
                                      "source_rows_sha256": source_rows}).decode()
        if (len(events) != 1 or tuple(events[0])[1:] !=
                ("local-root", "database.schema_migrated", "controller", "SUCCEEDED", expected_details)
                or (migrated_rows, migrated_counts) != (source_rows, counts)):
            raise Denied("MIGRATION_REVIEW_MISMATCH")
        _, new_tables = migration_script(after)
        for name in new_tables:
            if db.execute(f'SELECT 1 FROM "{name}" LIMIT 1').fetchone():
                raise Denied("MIGRATION_REVIEW_MISMATCH")

    facts = {"source_snapshot_sha256": snapshot.hexdigest(), "source_rows_sha256": source_rows,
             "source_audit_sequence": sequence, "source_audit_head": source_head,
             "migrated_audit_sequence": events[0]["seq"], "migrated_audit_head": migrated_head,
             "preserved_table_rows": counts}
    if canonical(facts) != canonical({key: report.get(key) for key in facts}):
        raise Denied("MIGRATION_REVIEW_MISMATCH")
    if expired():
        raise Denied("MIGRATION_REVIEW_TIMEOUT")
    return {"status": "REHEARSAL_VERIFIED", "schema_before": before, "schema_after": after,
            "source_rows_sha256": source_rows, "live_apply": "BLOCKED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify the saved SQLite migration rehearsal output")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify_rehearsal(args.directory)))
        return 0
    except (Denied, OSError, RuntimeError, sqlite3.Error, ValueError) as error:
        print(error.code if isinstance(error, Denied) else "MIGRATION_REVIEW_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
