"""Historical rows, WAL snapshots and crash atomicity of a copy-only migration."""

from contextlib import closing
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from hostorbit.auth import AuthService
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.migrations import expected_schema, historical_schema, rehearse, schema_rows
from hostorbit.queue import JobQueue


def kill_during_migration(path, output):
    def kill(*args, **kwargs):
        os.kill(os.getpid(), signal.SIGKILL)
    with patch.object(Store, "event", side_effect=kill):
        rehearse(Store(path), output)


def kill_after_commit(path, output):
    from hostorbit import migrations
    migrate = migrations._migrate_snapshot
    def commit_then_kill(*args, **kwargs):
        migrate(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    with patch.object(migrations, "_migrate_snapshot", side_effect=commit_then_kill):
        rehearse(Store(path), output)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source = self.root / "live"
        source.mkdir(mode=0o700)
        self.store = Store(source / "controller.sqlite3")
        self.store.path.touch(mode=0o600)
        with closing(sqlite3.connect(self.store.path, autocommit=True)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(historical_schema())
        self.auth = AuthService(self.store)
        self.owner = self.auth.create_owner(self.auth.issue_bootstrap(), "roman", "Fixture-owner-password-117!")
        self.tokens, _ = self.auth.login("roman", "Fixture-owner-password-117!", ip="192.0.2.77", correlation="fixture")
        self.output = self.root / "rehearsal"

    def report(self):
        return json.loads((self.output / "rehearsal.json").read_bytes())

    def source_state(self):
        with self.store.connect(readonly=True) as db:
            return (db.execute("PRAGMA user_version").fetchone()[0], self.store.verify_audit(),
                    [tuple(row) for row in db.execute("SELECT * FROM users")],
                    [tuple(row) for row in db.execute("SELECT * FROM sessions")], schema_rows(db))

    def test_preserves_users_hashes_sessions_grants_and_audit_on_coherent_copies(self):
        with self.store.write() as db:
            db.execute("INSERT INTO grants VALUES(?,?,?)", (self.owner, "vps:probe", identifier()))
        before = self.source_state()
        report = rehearse(self.store, self.output)
        self.assertEqual(report["status"], "REHEARSAL_PASSED")
        self.assertEqual(self.source_state(), before)
        self.assertFalse(report["applied_to_source"])
        self.assertEqual(report["live_apply"], "BLOCKED")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(report, self.report())
        copied = Store(self.output / "migrated.sqlite3")
        self.assertEqual(copied.verify_audit(), report["migrated_audit_head"])
        with copied.connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(schema_rows(db), expected_schema(2))
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM users")], before[2])
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM sessions")], before[3])
            self.assertEqual(db.execute("SELECT count(*) FROM grants").fetchone()[0], 1)
            event = db.execute("SELECT event,details FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertEqual(event["event"], "database.schema_migrated")
            self.assertTrue(json.loads(event["details"])["rehearsal"])
            password_hash = db.execute("SELECT password_hash FROM users").fetchone()[0]
        # The session is usable on the migrated copy without recreating Owner.
        principal = AuthService(copied).authenticate(self.tokens.session, ip="192.0.2.77")
        self.assertEqual(principal.id, self.owner)
        self.assertIsNone(JobQueue(copied).claim(identifier()))
        rendered = json.dumps(report)
        for secret in (password_hash, self.tokens.session, self.tokens.csrf, "Fixture-owner-password-117!"):
            self.assertNotIn(secret, rendered)

    def test_uses_committed_wal_not_only_the_main_database_file(self):
        with self.store.connect() as keeper:
            keeper.execute("PRAGMA wal_autocheckpoint=0")
            with self.store.write() as db:
                self.store.event(db, at=123, actor="fixture", kind="fixture.wal_only", target="controller",
                                 outcome="SUCCEEDED", correlation="fixture")
            self.assertGreater(Path(str(self.store.path) + "-wal").stat().st_size, 0)
            before = self.source_state()
            report = rehearse(self.store, self.output)
            self.assertEqual(report["source_audit_head"], before[1])
            with Store(self.output / "source.sqlite3").connect(readonly=True) as db:
                self.assertEqual(db.execute("SELECT event FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0], "fixture.wal_only")
            self.assertEqual(self.source_state(), before)

    def test_concurrent_writer_cannot_mix_two_snapshot_points(self):
        head_before = self.store.verify_audit()
        written = False
        def clock():
            nonlocal written
            if not written and (self.output / "source.sqlite3").exists():
                written = True
                with self.store.write() as db:
                    self.store.event(db, at=456, actor="fixture", kind="fixture.concurrent", target="controller",
                                     outcome="SUCCEEDED", correlation="fixture")
            return time.monotonic()
        report = rehearse(self.store, self.output, clock=clock)
        self.assertTrue(written)
        self.assertNotEqual(self.store.verify_audit(), head_before)
        self.assertEqual(report["source_audit_head"], head_before)
        self.assertEqual(Store(self.output / "source.sqlite3").verify_audit(), head_before)
        with Store(self.output / "migrated.sqlite3").connect(readonly=True) as db:
            self.assertFalse(db.execute("SELECT 1 FROM audit WHERE event='fixture.concurrent'").fetchone())

    def test_readonly_connection_cannot_write_or_initialize_the_source(self):
        with self.store.connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA query_only").fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "READONLY_INITIALIZATION"):
            with self.store.connect(readonly=True, initializing=True):
                pass

    def test_refuses_unknown_or_already_current_schema_without_altering_it(self):
        for version in (0, 2, 99):
            with self.subTest(version=version):
                with closing(sqlite3.connect(self.store.path)) as db:
                    db.execute(f"PRAGMA user_version={version}")
                output = self.root / f"schema-{version}"
                with self.assertRaises((Denied, RuntimeError)):
                    rehearse(self.store, output)
                with closing(sqlite3.connect(self.store.path)) as db:
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], version)
                self.assertEqual(json.loads((output / "rehearsal.json").read_bytes())["status"], "FAILED")

    def test_schema_version_number_does_not_hide_extra_tables_or_missing_constraints(self):
        with self.store.connect() as db:
            db.execute("CREATE TABLE unexpected(value TEXT)")
        with self.assertRaisesRegex(Denied, "SCHEMA_DRIFT"):
            rehearse(self.store, self.output)
        self.assertEqual(self.report()["status"], "FAILED")
        self.assertFalse((self.output / "migrated.sqlite3").exists())

    def test_similarly_named_sqlite_user_table_is_not_hidden_as_an_internal_table(self):
        with self.store.connect() as db:
            db.execute("CREATE TABLE sqliteXshadow(value TEXT)")
        with self.assertRaisesRegex(Denied, "SCHEMA_DRIFT"):
            rehearse(self.store, self.output)

    def test_matching_schema_with_broken_audit_chain_is_rejected(self):
        with self.store.connect() as db:
            sql = db.execute("SELECT sql FROM sqlite_schema WHERE name='audit_no_update'").fetchone()[0]
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET outcome='FORGED' WHERE seq=1")
            db.execute(sql)
        with self.assertRaisesRegex(RuntimeError, "AUDIT_INTEGRITY"):
            rehearse(self.store, self.output)
        self.assertEqual(self.report()["status"], "FAILED")

    def test_foreign_key_violation_in_a_matching_schema_is_rejected(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute("INSERT INTO grants VALUES('missing','vps:probe','fixture')")
            db.commit()
        with self.assertRaisesRegex(Denied, "SOURCE_CORRUPT"):
            rehearse(self.store, self.output)
        self.assertEqual(self.report()["status"], "FAILED")

    def test_failed_audit_commit_rolls_back_schema_ddl_and_version_on_the_copy(self):
        before = self.source_state()
        with patch.object(Store, "event", side_effect=sqlite3.IntegrityError("fixture outbox unavailable")):
            with self.assertRaises(sqlite3.IntegrityError):
                rehearse(self.store, self.output)
        copied = Store(self.output / "migrated.sqlite3")
        with copied.connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(schema_rows(db), expected_schema(1))
        self.assertEqual(self.report()["status"], "FAILED")
        self.assertEqual(self.source_state(), before)

    def test_sigkill_between_ddl_and_audit_leaves_no_mixed_schema_or_success_report(self):
        before = self.source_state()
        process = multiprocessing.get_context("fork").Process(target=kill_during_migration, args=(self.store.path, self.output))
        process.start()
        process.join(20)
        if process.is_alive():
            process.kill()
            process.join(5)
            self.fail("Migration fixture did not terminate")
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        process.close()
        self.assertEqual(self.report()["status"], "RUNNING")
        with Store(self.output / "migrated.sqlite3").connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(schema_rows(db), expected_schema(1))
        self.assertEqual(self.source_state(), before)

    def test_sigkill_after_commit_preserves_schema_two_but_does_not_claim_a_pass(self):
        before = self.source_state()
        process = multiprocessing.get_context("fork").Process(target=kill_after_commit, args=(self.store.path, self.output))
        process.start()
        process.join(20)
        if process.is_alive():
            process.kill()
            process.join(5)
            self.fail("Migration fixture did not terminate")
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        process.close()
        self.assertEqual(self.report()["status"], "RUNNING")
        copied = Store(self.output / "migrated.sqlite3")
        copied.verify_audit()
        with copied.connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(schema_rows(db), expected_schema(2))
        self.assertEqual(self.source_state(), before)

    def test_expired_copy_budget_and_existing_output_never_replace_live_or_previous_files(self):
        before = self.source_state()
        ticks = iter((0, 31))
        with self.assertRaisesRegex(Denied, "TIMEOUT"):
            rehearse(self.store, self.output, clock=lambda: next(ticks, 31))
        self.assertEqual(self.report()["status"], "FAILED")
        original = (self.output / "rehearsal.json").read_bytes()
        with self.assertRaises(FileExistsError):
            rehearse(self.store, self.output)
        self.assertEqual((self.output / "rehearsal.json").read_bytes(), original)
        self.assertEqual(self.source_state(), before)

    def test_output_symlink_cannot_overwrite_an_existing_directory(self):
        self.output.symlink_to(self.store.path.parent, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            rehearse(self.store, self.output)
        self.assertFalse((self.store.path.parent / "rehearsal.json").exists())


class PlanDraftMigrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store.initialize(self.root / "live" / "controller.sqlite3")
        auth = AuthService(self.store)
        password = "Fixture-owner-password-117!"
        auth.create_owner(auth.issue_bootstrap(), "roman", password)
        tokens, _ = auth.login("roman", password, ip="192.0.2.77", correlation="fixture")
        queue = JobQueue(self.store)
        resource = identifier()
        queue.register_resource(resource, "a" * 64, 1)
        queue.enqueue_probe(auth, tokens.session, tokens.csrf, resource, identifier())
        claim, row = queue.claim(identifier())
        queue.advance(claim, "INTENT_PREPARED", permit={"claims": queue.binding(row)})
        queue.advance(claim, "DISPATCHING")
        queue.finish(claim, "UNKNOWN_OUTCOME", "SSH_TIMEOUT")
        self.output = self.root / "schema-three"

    def test_rehearses_plan_schema_on_a_copy_without_losing_queue_rows(self):
        tables = ("resources", "jobs", "request_keys", "job_incidents")
        with self.store.read() as db:
            before = {name: [tuple(row) for row in db.execute(f'SELECT * FROM "{name}"')] for name in tables}
        head = self.store.verify_audit()
        report = rehearse(self.store, self.output, to_schema=3)
        self.assertEqual(report["status"], "REHEARSAL_PASSED")
        self.assertEqual((report["schema_before"], report["schema_after"]), (2, 3))
        self.assertEqual(report["source_audit_head"], head)
        self.assertEqual(self.store.verify_audit(), head)
        self.assertEqual(report["live_apply"], "BLOCKED")
        for name in tables:
            self.assertEqual(report["preserved_table_rows"][name], 1)
        for file, version in (("source.sqlite3", 2), ("migrated.sqlite3", 3)):
            with closing(sqlite3.connect(self.output / file)) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (version,))
                for name in tables:
                    self.assertEqual(db.execute(f'SELECT * FROM "{name}"').fetchall(), before[name])
                if version == 3:
                    self.assertEqual(db.execute("SELECT count(*) FROM change_plan_drafts").fetchone(), (0,))
                    details = db.execute("SELECT details FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0]
                    self.assertEqual(json.loads(details)["to_schema"], 3)
        with self.store.read() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(schema_rows(db), expected_schema(2))
        with self.assertRaisesRegex(RuntimeError, "DATABASE_CONTRACT_MISMATCH"):
            with Store(self.output / "migrated.sqlite3").connect():
                pass
        with self.assertRaisesRegex(Denied, "MIGRATION_SCHEMA_UNSUPPORTED"):
            expected_schema(3)

    def test_rolls_back_plan_schema_when_audit_commit_fails(self):
        head = self.store.verify_audit()
        with patch.object(Store, "event", side_effect=sqlite3.IntegrityError("fixture outbox unavailable")):
            with self.assertRaises(sqlite3.IntegrityError):
                rehearse(self.store, self.output, to_schema=3)
        with Store(self.output / "migrated.sqlite3").connect(readonly=True) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(schema_rows(db), expected_schema(2))
            self.assertEqual(Store.verify_audit_connection(db), head)
        report = json.loads((self.output / "rehearsal.json").read_bytes())
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(self.store.verify_audit(), head)


if __name__ == "__main__":
    unittest.main()
