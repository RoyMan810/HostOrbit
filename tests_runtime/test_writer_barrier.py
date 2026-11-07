import errno
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
from threading import Event, Thread
import time
import unittest
from unittest.mock import patch

from hostorbit.admission import Admission
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.runtime.coordinator import Coordinator


def write_child(database, directory, started, committed):
    store = Store(database, writers=Admission(directory, owner=os.geteuid()))
    started.set()
    with store.write(kind="control") as db:
        Store.event(db, at=1, actor="fixture", kind="checkpoint", target="fixture", outcome="SUCCEEDED", correlation="fixture")
    committed.set()


def crash_child(directory, state, stop_phase, reached):
    coordinator = Coordinator(directory, Admission(state, owner=os.geteuid()))
    original = coordinator._transition

    def stop(snapshot_id, phase, *args, **kwargs):
        original(snapshot_id, phase, *args, **kwargs)
        if phase == stop_phase:
            reached.set()
            time.sleep(120)

    coordinator._transition = stop
    coordinator.snapshot(lambda: True, lambda _: None)


class WriterBarrierTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.admission = Admission.initialize(self.root / "public", owner=os.geteuid())
        self.coordinator = Coordinator.initialize(self.root / "control", self.admission)
        self.store = Store.initialize(self.root / "app" / "controller.sqlite3")
        self.store.writers = self.admission

    def event(self, kind="control"):
        with self.store.write(kind=kind) as db:
            self.store.event(db, at=1, actor="fixture", kind="checkpoint", target="fixture", outcome="SUCCEEDED", correlation="fixture")

    def phases(self):
        with self.coordinator.journal.connect() as db:
            return [row["phase"] for row in db.execute("SELECT phase FROM transitions ORDER BY seq")]

    def test_closing_rejects_new_work_but_commits_checkpoint_and_outbox(self):
        self.admission.publish("CLOSING_ADMISSION", identifier())
        for kind in ("business", "dispatch"):
            with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
                self.event(kind)
        self.event()
        self.store.verify_audit()
        self.assertEqual(len(self.store.events_after(0)), 1)

    def test_blocked_writer_takes_no_sqlite_transaction_before_admission(self):
        ctx = multiprocessing.get_context("spawn")
        started, committed = ctx.Event(), ctx.Event()
        self.admission.publish("SHORT_BARRIER", identifier())
        child = ctx.Process(target=write_child, args=(self.store.path, self.admission.directory, started, committed))
        try:
            with self.admission.exclusive(timeout=1):
                child.start()
                self.assertTrue(started.wait(10))
                self.assertFalse(committed.wait(0.1))
                # Root-only test probe: a writer blocked by the barrier has not
                # acquired BEGIN IMMEDIATE on the snapshot-critical database.
                with sqlite3.connect(self.store.path, timeout=0.1) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.rollback()
                self.admission.publish("OPEN")
            self.assertTrue(committed.wait(10))
            child.join(10)
            self.assertEqual(child.exitcode, 0)
        finally:
            if child.is_alive():
                child.kill()
                child.join(5)
        self.store.verify_audit()

    def test_existing_writer_commits_before_capture_and_local_io_runs_under_exclusion(self):
        entered, release, done = Event(), Event(), Event()
        errors = []

        def writer():
            try:
                with self.store.write() as db:
                    entered.set()
                    release.wait(5)
                    self.store.event(db, at=1, actor="fixture", kind="checkpoint", target="fixture", outcome="SUCCEEDED", correlation="fixture")
                done.set()
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=writer)
        thread.start()
        self.assertTrue(entered.wait(5))

        def drain():
            # ACK/checkpoint transactions may still finish in CLOSING_ADMISSION.
            release.set()
            return done.is_set()

        def capture(_):
            self.assertEqual(self.admission.state()["phase"], "SHORT_BARRIER")
            self.assertTrue(done.is_set())
            blocked = Admission(self.admission.directory, owner=os.geteuid(), timeout=0.03)
            with self.assertRaisesRegex(Denied, "WRITER_BARRIER_TIMEOUT"):
                with blocked.writer("control"):
                    self.fail("critical writer entered the barrier")
            return self.store.verify_audit()

        try:
            _, audit_head = self.coordinator.snapshot(drain, capture, drain_timeout=3, barrier_timeout=3)
        finally:
            release.set()
            thread.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(audit_head, self.store.verify_audit())
        self.assertEqual(self.phases(), ["REQUESTED", "CLOSING_ADMISSION", "SHORT_BARRIER", "BARRIER_RELEASED"])
        self.event("business")  # Slow encryption/upload would occur after here.

    def test_drain_and_capture_deadlines_interrupt_blocking_callbacks_and_abort(self):
        for phase in ("drain", "capture"):
            with self.subTest(phase=phase):
                started = time.monotonic()
                def slow(*_):
                    time.sleep(2)
                with self.assertRaisesRegex(Denied, "SNAPSHOT_" + ("DRAIN" if phase == "drain" else "BARRIER") + "_TIMEOUT"):
                    self.coordinator.snapshot(slow if phase == "drain" else lambda: True,
                                              slow, drain_timeout=0.06, barrier_timeout=0.06)
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(self.phases()[-1], "ABORTED")
                self.event("business")

    def test_enospc_control_journal_never_reopens_business_admission(self):
        with patch.object(self.coordinator.journal, "write", side_effect=OSError(errno.ENOSPC, "fixture full disk")):
            with self.assertRaises(OSError):
                self.coordinator.snapshot(lambda: True, lambda _: None)
            self.assertNotEqual(self.admission.state()["phase"], "OPEN")
            with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
                self.event("business")
            with self.assertRaises(OSError):
                self.coordinator.recover()
        self.coordinator.recover()
        self.assertEqual(self.phases(), ["ABORTED"])
        self.event("business")

    def test_enospc_state_publication_removes_old_open_latch_until_recovery(self):
        original = os.open
        def full(name, *args, **kwargs):
            if str(name).startswith(".state-"):
                raise OSError(errno.ENOSPC, "fixture full disk")
            return original(name, *args, **kwargs)
        with patch("hostorbit.admission.os.open", side_effect=full):
            with self.assertRaises(OSError):
                self.admission.publish("CLOSING_ADMISSION", identifier())
        self.assertFalse((self.admission.directory / "state.json").exists())
        with self.assertRaisesRegex(Denied, "WRITER_STATE_UNAVAILABLE"):
            self.event("business")
        self.coordinator.recover()
        self.event("business")

    def test_killed_coordinator_stays_closed_until_durable_recovery_in_every_local_phase(self):
        ctx = multiprocessing.get_context("spawn")
        for phase in ("REQUESTED", "CLOSING_ADMISSION", "SHORT_BARRIER", "BARRIER_RELEASED"):
            with self.subTest(phase=phase):
                reached = ctx.Event()
                child = ctx.Process(target=crash_child, args=(self.coordinator.directory, self.admission.directory, phase, reached))
                child.start()
                try:
                    self.assertTrue(reached.wait(10))
                    self.coordinator.recover_if_idle()
                    self.assertNotEqual(self.admission.state()["phase"], "OPEN")
                    child.kill()
                    child.join(5)
                    self.assertNotEqual(self.admission.state()["phase"], "OPEN")
                    with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED|WRITER_BARRIER_TIMEOUT"):
                        with Admission(self.admission.directory, owner=os.geteuid(), timeout=0.03).writer():
                            self.fail("admitted after coordinator SIGKILL")
                    self.coordinator.recover_if_idle()
                    self.assertEqual(self.phases()[-1], "ABORTED")
                    self.event("business")
                finally:
                    if child.is_alive():
                        child.kill()
                        child.join(5)

    def test_corrupt_or_replaced_public_files_fail_closed(self):
        state = self.admission.directory / "state.json"
        saved = state.read_bytes()
        for raw in (b"{}", b'{"phase":[]}', b"not json", saved + b"\n"):
            with self.subTest(raw=raw):
                state.write_bytes(raw)
                with self.assertRaisesRegex(Denied, "WRITER_STATE_INVALID"):
                    self.event("business")
        state.write_bytes(saved)
        lock = self.admission.directory / "writers.lock"
        lock.unlink()
        lock.symlink_to(state)
        with self.assertRaisesRegex(Denied, "WRITER_STATE_UNAVAILABLE"):
            self.event("business")

    def test_failed_business_transaction_releases_lock_and_remains_rolled_back(self):
        with self.assertRaises(OSError):
            with self.store.write() as db:
                self.store.event(db, at=1, actor="fixture", kind="checkpoint", target="fixture", outcome="SUCCEEDED", correlation="fixture")
                raise OSError(errno.ENOSPC, "fixture failed write")
        self.assertEqual(self.store.events_after(0), [])
        self.coordinator.snapshot(lambda: True, lambda _: self.store.verify_audit())


if __name__ == "__main__":
    unittest.main()
