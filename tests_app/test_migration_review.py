from contextlib import closing, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from hostorbit.database import Store
from hostorbit.errors import Denied
from hostorbit.migrations import historical_schema, rehearse
from hostorbit.runtime.migration_review import main, verify_rehearsal
from hostorbit.runtime.protocol import canonical


class MigrationReviewTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        store = Store.initialize(root / "controller" / "controller.sqlite3", schema=2)
        with store.write() as db:
            Store.event(db, at=1, actor="fixture", kind="fixture.started", target="controller",
                        outcome="SUCCEEDED", correlation="fixture")
        self.output = root / "review"
        self.report = rehearse(store, self.output, to_schema=3)
        self.report_path = self.output / "rehearsal.json"

    def test_revalidates_the_private_copies_and_keeps_live_apply_blocked(self):
        copies = {name: (self.output / name).read_bytes() for name in ("source.sqlite3", "migrated.sqlite3")}
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([str(self.output)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "REHEARSAL_VERIFIED")
        self.assertEqual((result["schema_before"], result["schema_after"]), (2, 3))
        self.assertEqual(result["source_rows_sha256"], self.report["source_rows_sha256"])
        self.assertEqual(result["live_apply"], "BLOCKED")
        self.assertEqual(copies, {name: (self.output / name).read_bytes() for name in copies})

    def test_accepts_a_historical_one_to_two_rehearsal(self):
        folder = self.output.parent / "historical"
        folder.mkdir(mode=0o700)
        database = folder / "controller.sqlite3"
        database.touch(mode=0o600)
        with closing(sqlite3.connect(database, autocommit=True)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(historical_schema())
        output = self.output.parent / "review-historical"
        rehearse(Store(database), output)
        verified = verify_rehearsal(output)
        self.assertEqual((verified["schema_before"], verified["schema_after"]), (1, 2))

    def test_rejects_running_and_tampered_reports(self):
        for field, value in (("status", "RUNNING"), ("migrated_audit_head", "0" * 64),
                             ("preserved_table_rows", {}), ("source_snapshot_sha256", "0" * 64)):
            with self.subTest(field=field):
                self.report_path.write_bytes(canonical({**self.report, field: value}))
                with self.assertRaises(Denied):
                    verify_rehearsal(self.output)

    def test_rejects_drift_and_extra_audit_even_if_the_audit_chain_is_valid(self):
        with closing(sqlite3.connect(self.output / "migrated.sqlite3", autocommit=True)) as db:
            db.execute("BEGIN IMMEDIATE")
            Store.event(db, at=2, actor="fixture", kind="fixture.changed", target="controller",
                        outcome="SUCCEEDED", correlation="fixture")
            db.execute("COMMIT")
        with self.assertRaisesRegex(Denied, "MIGRATION_REVIEW_MISMATCH"):
            verify_rehearsal(self.output)
        with closing(sqlite3.connect(self.output / "migrated.sqlite3")) as db:
            db.execute("CREATE TABLE drift(value TEXT)")
        with self.assertRaisesRegex(Denied, "MIGRATION_SCHEMA_DRIFT"):
            verify_rehearsal(self.output)

    def test_rejects_a_changed_source_copy(self):
        with closing(sqlite3.connect(self.output / "source.sqlite3", autocommit=True)) as db:
            db.execute("BEGIN IMMEDIATE")
            Store.event(db, at=2, actor="fixture", kind="fixture.changed", target="controller",
                        outcome="SUCCEEDED", correlation="fixture")
            db.execute("COMMIT")
        with self.assertRaisesRegex(Denied, "MIGRATION_REVIEW_MISMATCH"):
            verify_rehearsal(self.output)
