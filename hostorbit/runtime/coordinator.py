"""Durable, bounded local snapshot barrier; sealing and transport run after it.

This is a coordination primitive, not an off-host backup or a Backup Gate proof.
Only trusted host code supplies the non-networking drain/capture callbacks.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import signal
from threading import current_thread, main_thread
import time

from ..admission import Admission
from ..database import identifier
from ..errors import Denied
from .storage import Journal, new_private_file, process_lock
from .protocol import canonical


_SCHEMA = """
CREATE TABLE snapshots(id TEXT PRIMARY KEY, phase TEXT NOT NULL, reason TEXT);
CREATE TABLE transitions(seq INTEGER PRIMARY KEY AUTOINCREMENT, snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    phase TEXT NOT NULL, reason TEXT, boot_id TEXT NOT NULL, monotonic_ns INTEGER NOT NULL);
CREATE TRIGGER transitions_no_update BEFORE UPDATE ON transitions BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
CREATE TRIGGER transitions_no_delete BEFORE DELETE ON transitions BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
"""
_NEXT = {"REQUESTED": "CLOSING_ADMISSION", "CLOSING_ADMISSION": "SHORT_BARRIER", "SHORT_BARRIER": "BARRIER_RELEASED",
         "BARRIER_RELEASED": "SEALED", "SEALED": "SIGNED"}


class _Expired(BaseException):
    pass


@contextmanager
def _deadline(seconds):
    # A synchronous root CLI can interrupt blocking local I/O, not just check a
    # deadline after an unbounded callback. Do not run in a thread or mask an
    # existing caller timer. SIGKILL is handled by durable restart recovery.
    if current_thread() is not main_thread() or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise Denied("SNAPSHOT_DEADLINE_UNAVAILABLE", 503)
    previous = signal.getsignal(signal.SIGALRM)

    def expired(*_):
        raise _Expired()

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Coordinator:
    def __init__(self, directory, admission: Admission):
        self.directory = Path(directory)
        self.admission = admission
        self.journal = Journal(self.directory / "snapshots.sqlite3")

    @classmethod
    def initialize(cls, directory, admission):
        if os.geteuid() != admission.owner:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        coordinator = cls(directory, admission)
        Journal.initialize(coordinator.journal.path, _SCHEMA)
        coordinator.recover()
        return coordinator

    def _transition(self, snapshot_id, phase, reason=None, *, recovering=False):
        with self.journal.write() as db:
            old = db.execute("SELECT phase FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if old is None:
                if phase != "REQUESTED" and not (recovering and phase == "ABORTED"):
                    raise Denied("SNAPSHOT_TRANSITION_DENIED")
                db.execute("INSERT INTO snapshots VALUES(?,?,?)", (snapshot_id, phase, reason))
            else:
                if (phase != _NEXT.get(old["phase"]) and not
                        (phase == "ABORTED" and old["phase"] in {"REQUESTED", "CLOSING_ADMISSION", "SHORT_BARRIER", "BARRIER_RELEASED"})
                        and not (phase == "FAILED" and old["phase"] in {"BARRIER_RELEASED", "SEALED", "SIGNED"})):
                    raise Denied("SNAPSHOT_TRANSITION_DENIED")
                db.execute("UPDATE snapshots SET phase=?,reason=? WHERE id=?", (phase, reason, snapshot_id))
            db.execute("INSERT INTO transitions(snapshot_id,phase,reason,boot_id,monotonic_ns) VALUES(?,?,?,?,?)",
                       (snapshot_id, phase, reason, Path("/proc/sys/kernel/random/boot_id").read_text().strip(), time.monotonic_ns()))

    def recover(self):
        """Abort incomplete local captures before opening admission after restart.

        The process lock rejects recovery while a live coordinator is running.
        A corrupt/unwritable journal never opens the public latch.
        """
        if os.geteuid() != self.admission.owner:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        with process_lock(self.directory / "coordinator.lock"):
            try:
                state = self.admission.state()
            except Denied as error:
                if error.code != "WRITER_STATE_UNAVAILABLE" or os.path.lexists(self.admission.directory / "state.json"):
                    raise
                state = {"phase": "RECOVERY_HOLD", "snapshot_id": None}
            with self.journal.connect() as db:
                unfinished = [row["id"] for row in db.execute("SELECT id FROM snapshots WHERE phase IN ('REQUESTED','CLOSING_ADMISSION','SHORT_BARRIER')")]
            token = state["snapshot_id"]
            if state["phase"] == "OPEN" and not unfinished:
                return
            self.admission.publish("RECOVERY_HOLD", token)
            for snapshot_id in set(unfinished + ([token] if token else [])):
                with self.journal.connect() as db:
                    row = db.execute("SELECT phase FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
                if row is None or row["phase"] not in {"ABORTED", "FAILED"}:
                    phase = "FAILED" if row is not None and row["phase"] in {"SEALED", "SIGNED"} else "ABORTED"
                    self._transition(snapshot_id, phase, "COORDINATOR_RESTART", recovering=True)
            # Status is durable before reopening. Existing control transactions
            # are allowed to finish; no snapshot is being taken during recovery.
            self.admission.publish("OPEN")

    def recover_if_idle(self):
        """Supervisor watchdog: never steal the lock from a live coordinator."""
        try:
            if self.admission.state()["phase"] == "OPEN":
                return
        except Denied as error:
            if error.code != "WRITER_STATE_UNAVAILABLE":
                raise
        try:
            self.recover()
        except Denied as error:
            if error.code != "PROCESS_ALREADY_RUNNING":
                raise

    def snapshot(self, drain, capture, *, drain_timeout=60, barrier_timeout=30, metadata=None):
        """Return (id, local result) only after all critical writers are released.

        drain() polls active work without holding SQLite write transactions;
        capture(id) performs only bounded local pin/copy/fsync operations. Never
        wait for a Job, call a service RPC, encrypt, sign or upload inside capture.
        """
        if os.geteuid() != self.admission.owner:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        if not 0 < drain_timeout <= 60 or not 0 < barrier_timeout <= 30:
            raise ValueError("SNAPSHOT_DEADLINE_INVALID")
        with process_lock(self.directory / "coordinator.lock"):
            if self.admission.state()["phase"] != "OPEN":
                raise Denied("SNAPSHOT_RECOVERY_REQUIRED", 503)
            with self.journal.connect() as db:
                if db.execute("SELECT 1 FROM snapshots WHERE phase IN ('REQUESTED','CLOSING_ADMISSION','SHORT_BARRIER')").fetchone():
                    self.admission.publish("RECOVERY_HOLD")
                    raise Denied("SNAPSHOT_RECOVERY_REQUIRED", 503)
            snapshot_id = identifier()
            # Close before the first journal write: even ENOSPC here must deny
            # new business admission until explicit durable recovery succeeds.
            deadline_stage = "DRAIN"
            try:
                with _deadline(drain_timeout):
                    self.admission.publish("CLOSING_ADMISSION", snapshot_id)
                    if metadata is not None:
                        raw = canonical(metadata)
                        if len(raw) > 16384:
                            raise Denied("SNAPSHOT_REQUEST_INVALID")
                        requests = self.directory / "requests"
                        requests.mkdir(mode=0o700, exist_ok=True)
                        new_private_file(requests / (snapshot_id + ".json"), raw)
                    self._transition(snapshot_id, "REQUESTED")
                    self._transition(snapshot_id, "CLOSING_ADMISSION")
                    while not drain():
                        time.sleep(0.01)
                deadline_stage = "BARRIER"
                with _deadline(barrier_timeout):
                    self.admission.publish("SHORT_BARRIER", snapshot_id)
                    self._transition(snapshot_id, "SHORT_BARRIER")
                    with self.admission.exclusive(timeout=barrier_timeout):
                        result = capture(snapshot_id)
                        self._transition(snapshot_id, "BARRIER_RELEASED")
                        self.admission.publish("OPEN")
                return snapshot_id, result
            except BaseException as error:
                reason = f"SNAPSHOT_{deadline_stage}_TIMEOUT" if isinstance(error, _Expired) else "SNAPSHOT_CAPTURE_FAILED"
                # If either commit or publication fails, leave the latch closed.
                self.admission.publish("RECOVERY_HOLD", snapshot_id)
                self._transition(snapshot_id, "ABORTED", reason, recovering=True)
                self.admission.publish("OPEN")
                if isinstance(error, _Expired):
                    raise Denied(reason, 503) from None
                raise
