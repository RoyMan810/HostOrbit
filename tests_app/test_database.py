from contextlib import closing, redirect_stderr, redirect_stdout
from io import StringIO
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest

from hostorbit.cli import main
from hostorbit.database import Store


def die_before_commit(path):
    store = Store(path)
    with store.write() as db:
        store.event(db, at=1, actor="fixture", kind="fixture", target="fixture", outcome="SUCCEEDED", correlation="fixture")
        os.kill(os.getpid(), signal.SIGKILL)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store.initialize(self.directory / "controller.sqlite3")

    def record(self, db):
        return self.store.event(db, at=1, actor="actor", kind="fixture", target="target", outcome="SUCCEEDED", correlation="request")

    def test_pragmas_private_files_unknown_schema_and_missing_database_fail_closed(self):
        with self.store.connect() as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(db.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(db.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            db.execute("PRAGMA user_version=99")
        with self.assertRaisesRegex(RuntimeError, "DATABASE_CONTRACT"):
            with self.store.connect():
                pass
        with self.assertRaises(FileNotFoundError):
            with Store(self.directory / "missing.sqlite3").connect():
                pass
        self.assertFalse((self.directory / "missing.sqlite3").exists())
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "DATABASE_PERMISSIONS"):
            with self.store.connect():
                pass

    def test_symlink_database_and_shared_parent_are_rejected(self):
        link = self.directory / "alias.sqlite3"
        link.symlink_to(self.store.path)
        with self.assertRaisesRegex(RuntimeError, "DATABASE_PERMISSIONS"):
            with Store(link).connect():
                pass
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "DATABASE_DIRECTORY_PERMISSIONS"):
            Store.initialize(self.directory / "second.sqlite3")

    def test_outbox_failure_rolls_back_state_and_audit_together(self):
        with self.store.connect() as db:
            db.execute("CREATE TABLE fixture_state(id INTEGER)")
            db.executescript("CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture full'); END;")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.write() as db:
                db.execute("INSERT INTO fixture_state VALUES(1)")
                self.record(db)
        with self.store.connect() as db:
            for table in ("fixture_state", "audit", "outbox"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_kill_before_commit_does_not_publish_uncommitted_events(self):
        child = multiprocessing.get_context("spawn").Process(target=die_before_commit, args=(self.store.path,))
        child.start()
        child.join(15)
        if child.is_alive():
            child.kill()
            child.join(5)
            self.fail("Fixture did not terminate")
        self.assertEqual(child.exitcode, -signal.SIGKILL)
        child.close()
        self.assertEqual(self.store.events_after(0), [])
        self.assertEqual(self.store.verify_audit(), "0" * 64)
        with self.store.write() as db:
            self.record(db)
        self.assertEqual(len(self.store.events_after(0)), 1)

    def test_audit_and_outbox_are_append_only_and_tampering_is_detected(self):
        with self.store.write() as db:
            self.record(db)
            self.record(db)
        head = self.store.verify_audit()
        self.assertEqual(len(head), 64)
        for table in ("audit", "outbox"):
            with self.subTest(table=table), self.store.connect() as db:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "APPEND_ONLY"):
                    db.execute(f"DELETE FROM {table}")
        with self.store.connect() as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET outcome='FORGED' WHERE seq=1")
        with self.assertRaisesRegex(RuntimeError, "AUDIT_INTEGRITY"):
            self.store.verify_audit()

    def test_audit_verification_detects_outbox_metadata_and_orphan_rows(self):
        with self.store.write() as db:
            self.record(db)
        with closing(sqlite3.connect(self.store.path, autocommit=True)) as db:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("DROP TRIGGER outbox_no_update")
            for column, forged in (("event_id", "forged"), ("created_at", 2)):
                with self.subTest(column=column):
                    original = db.execute(f"SELECT {column} FROM outbox").fetchone()[0]
                    db.execute(f"UPDATE outbox SET {column}=?", (forged,))
                    with self.assertRaisesRegex(RuntimeError, "OUTBOX_INTEGRITY"):
                        self.store.verify_audit()
                    db.execute(f"UPDATE outbox SET {column}=?", (original,))
            db.execute("INSERT INTO outbox VALUES(2, 'orphan', '{}', 1)")
        with self.assertRaisesRegex(RuntimeError, "OUTBOX_INTEGRITY"):
            self.store.verify_audit()

    def test_audit_verify_command_reports_head_and_fails_on_tampering(self):
        def run():
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["--database", str(self.store.path), "audit-verify"])
            return status, stdout.getvalue(), stderr.getvalue()

        for count in (0, 1):
            with self.subTest(count=count):
                if count:
                    with self.store.write() as db:
                        self.record(db)
                status, stdout, stderr = run()
                self.assertEqual((status, stderr), (0, ""))
                self.assertEqual(json.loads(stdout), {"status": "verified", "events": count,
                                                      "head": self.store.verify_audit()})
        with self.store.connect() as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET outcome='FORGED'")
        self.assertEqual(run(), (1, "", "HostOrbit command failed AUDIT_VERIFICATION_FAILED\n"))
