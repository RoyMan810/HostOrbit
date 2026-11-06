"""T0-2 local fixture for the backup write barrier and immutable Vault pins."""

import base64
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import time

from nacl.secret import Aead
from nacl.signing import SigningKey

from .journal import connect_journal, reserve_journal
from .recovery import SignedBackup, Snapshot, encrypt_source


class Phase(StrEnum):
    REQUESTED = "REQUESTED"
    CLOSING_ADMISSION = "CLOSING_ADMISSION"
    SHORT_BARRIER = "SHORT_BARRIER"
    BARRIER_RELEASED = "BARRIER_RELEASED"
    SEALED = "SEALED"
    SIGNED = "SIGNED"
    UPLOADING = "UPLOADING"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class Work(StrEnum):
    JOB = "job"
    ROTATION = "rotation"


class BackupDenied(RuntimeError):
    pass


_PRE_SNAPSHOT = (Phase.REQUESTED, Phase.CLOSING_ADMISSION, Phase.SHORT_BARRIER)
_BLOCKING = (Phase.CLOSING_ADMISSION, Phase.SHORT_BARRIER)
_CONTROLLER = """
    CREATE TABLE work (id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL);
    CREATE TABLE audit (seq INTEGER PRIMARY KEY, work_id TEXT NOT NULL, event TEXT NOT NULL);
    CREATE TABLE generations (version INTEGER PRIMARY KEY, wrapped TEXT NOT NULL);
    CREATE TABLE secret_refs (
        name TEXT PRIMARY KEY NOT NULL,
        version INTEGER NOT NULL REFERENCES generations(version),
        ciphertext TEXT NOT NULL
    );
    CREATE TABLE backups (id TEXT PRIMARY KEY NOT NULL, phase TEXT NOT NULL, reason TEXT);
    CREATE UNIQUE INDEX one_active_backup ON backups ((1))
        WHERE phase NOT IN ('PUBLISHED', 'FAILED', 'ABORTED');
    CREATE TABLE pins (
        backup_id TEXT NOT NULL REFERENCES backups(id),
        digest TEXT NOT NULL,
        PRIMARY KEY (backup_id, digest)
    );
    PRAGMA user_version = 1;
"""
_VAULT = """
    CREATE TABLE objects (digest TEXT PRIMARY KEY NOT NULL, data BLOB NOT NULL);
    PRAGMA user_version = 1;
"""
_LIVE_REFS = "SELECT ciphertext AS digest FROM secret_refs UNION SELECT wrapped FROM generations"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _dek_context(version: int) -> bytes:
    return f"hostorbit.stage0.dek/{version}".encode("ascii")


def secret_context(name: str, version: int) -> bytes:
    return f"hostorbit.stage0.secret/{version}/{name}".encode("utf-8")


@dataclass(frozen=True, repr=False)
class Capture:
    database: bytes
    generations: dict[int, str]
    ciphertexts: dict[str, bytes]
    wrapped: dict[str, bytes]

    def portable(self, wrapper: Aead) -> Snapshot:
        # The lab payload holds both the portable keys and their encrypted objects.
        exported = {
            "keys": {
                str(version): _encode(wrapper.decrypt(self.wrapped[ref], _dek_context(version)))
                for version, ref in self.generations.items()
            },
            "ciphertexts": {ref: _encode(data) for ref, data in self.ciphertexts.items()},
        }
        return Snapshot(self.database, json.dumps(exported, sort_keys=True).encode("ascii"))


class BackupLab:
    def __init__(self, root: Path, wrap_key: bytes):
        self._root = root.absolute()
        self._controller = self._root / "controller.sqlite3"
        self._vault = self._root / "vault.sqlite3"
        self._wrapper = Aead(wrap_key)

    @classmethod
    def create(cls, root: Path, wrap_key: bytes) -> "BackupLab":
        lab = cls(root, wrap_key)
        for path, schema in ((lab._controller, _CONTROLLER), (lab._vault, _VAULT)):
            reserve_journal(path)
            with connect_journal(path, initialize=True) as db:
                db.executescript("BEGIN IMMEDIATE;\n" + schema + "\nCOMMIT;")
        return lab

    @contextmanager
    def _write(self):
        with connect_journal(self._controller) as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")

    def admit(self, kind: Work) -> str:
        if not isinstance(kind, Work):
            raise ValueError("Unknown fixture work")
        with self._write() as db:
            if db.execute("SELECT 1 FROM backups WHERE phase IN (?, ?)", _BLOCKING).fetchone():
                raise BackupDenied("BUSINESS_ADMISSION_CLOSED")
            work_id = secrets.token_hex(16)
            db.execute("INSERT INTO work VALUES (?, ?)", (work_id, kind))
            db.execute("INSERT INTO audit (work_id, event) VALUES (?, 'admitted')", (work_id,))
            return work_id

    @staticmethod
    def _require_work(db, work_id, kind=None):
        row = db.execute("SELECT kind FROM work WHERE id = ?", (work_id,)).fetchone()
        if row is None or (kind is not None and row["kind"] != kind):
            raise BackupDenied("WORK_NOT_ADMITTED")

    def checkpoint(self, work_id: str) -> None:
        with self._write() as db:
            self._require_work(db, work_id)
            db.execute("INSERT INTO audit (work_id, event) VALUES (?, 'checkpoint')", (work_id,))

    @staticmethod
    def _complete(db, work_id):
        db.execute("INSERT INTO audit (work_id, event) VALUES (?, 'completed')", (work_id,))
        db.execute("DELETE FROM work WHERE id = ?", (work_id,))

    def finish_job(self, work_id: str) -> None:
        with self._write() as db:
            self._require_work(db, work_id, Work.JOB)
            self._complete(db, work_id)

    def finish_rotation(self, work_id: str, name: str, value: bytes) -> None:
        with self._write() as db:
            self._require_work(db, work_id, Work.ROTATION)
            version = db.execute("SELECT coalesce(max(version), 0) + 1 FROM generations").fetchone()[0]
            key = secrets.token_bytes(Aead.KEY_SIZE)
            wrapped = bytes(self._wrapper.encrypt(key, _dek_context(version)))
            ciphertext = bytes(Aead(key).encrypt(value, secret_context(name, version)))
            with connect_journal(self._vault) as vault:
                # Publish immutable objects first. A failed metadata commit leaves only garbage.
                vault.executemany(
                    "INSERT INTO objects VALUES (?, ?) ON CONFLICT(digest) DO NOTHING",
                    [(_digest(data), data) for data in (wrapped, ciphertext)],
                )
            db.execute("INSERT INTO generations VALUES (?, ?)", (version, _digest(wrapped)))
            db.execute(
                """INSERT INTO secret_refs VALUES (?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET version = excluded.version, ciphertext = excluded.ciphertext""",
                (name, version, _digest(ciphertext)),
            )
            db.execute("DELETE FROM generations WHERE version NOT IN (SELECT version FROM secret_refs)")
            self._complete(db, work_id)

    def collect_unused(self) -> set[str]:
        with self._write() as db:
            keep = {row["digest"] for row in db.execute(_LIVE_REFS + " UNION SELECT digest FROM pins")}
            with connect_journal(self._vault) as vault:
                garbage = {row["digest"] for row in vault.execute("SELECT digest FROM objects")} - keep
                vault.executemany("DELETE FROM objects WHERE digest = ?", ((ref,) for ref in garbage))
            return garbage

    def _request(self, backup_id: str) -> None:
        with self._write() as db:
            if db.execute("SELECT 1 FROM backups WHERE phase NOT IN ('PUBLISHED', 'FAILED', 'ABORTED')").fetchone():
                raise BackupDenied("BACKUP_ACTIVE")
            db.execute("INSERT INTO backups VALUES (?, ?, NULL)", (backup_id, Phase.REQUESTED))

    @staticmethod
    def _set_phase(db, backup_id, expected, target):
        updated = db.execute(
            "UPDATE backups SET phase = ? WHERE id = ? AND phase = ?", (target, backup_id, expected),
        )
        if updated.rowcount != 1:
            raise BackupDenied("BACKUP_PHASE_CHANGED")

    def _advance(self, backup_id: str, expected: Phase, target: Phase) -> None:
        with self._write() as db:
            self._set_phase(db, backup_id, expected, target)
            if target == Phase.PUBLISHED:
                db.execute("DELETE FROM pins WHERE backup_id = ?", (backup_id,))

    def _drain(self, backup_id: str, deadline: float) -> None:
        while time.monotonic() < deadline:
            with self._write() as db:
                if time.monotonic() >= deadline:
                    break
                if db.execute("SELECT 1 FROM work LIMIT 1").fetchone() is None:
                    self._set_phase(db, backup_id, Phase.CLOSING_ADMISSION, Phase.SHORT_BARRIER)
                    db.execute("INSERT INTO pins SELECT ?, digest FROM (" + _LIVE_REFS + ")", (backup_id,))
                    return
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        raise BackupDenied("DRAIN_TIMEOUT")

    def _capture(self, backup_id: str, deadline: float) -> Capture:
        def check_deadline(*_):
            if time.monotonic() >= deadline:
                raise BackupDenied("SNAPSHOT_TIMEOUT")

        check_deadline()
        with TemporaryDirectory(prefix=f"snapshot-{backup_id}-", dir=self._root) as directory:
            path = Path(directory) / "controller.sqlite3"
            # This temporary DB contains metadata and references, never DEKs or plaintext secrets.
            with connect_journal(self._controller) as source, closing(sqlite3.connect(path)) as dest:
                source.backup(dest, pages=16, progress=check_deadline, sleep=0.01)
                dest.execute("PRAGMA journal_mode = DELETE").fetchone()
                if dest.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise BackupDenied("SNAPSHOT_INTEGRITY")
                if dest.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise BackupDenied("SNAPSHOT_REFERENCES")
                versions = dict(dest.execute("SELECT version, wrapped FROM generations"))
                ciphertexts = {row[0] for row in dest.execute("SELECT ciphertext FROM secret_refs")}
                wrapped = set(versions.values())
                pinned = {row[0] for row in dest.execute("SELECT digest FROM pins WHERE backup_id = ?", (backup_id,))}
                if pinned != ciphertexts | wrapped:
                    raise BackupDenied("SNAPSHOT_PINS")
            database = path.read_bytes()

        with connect_journal(self._vault) as vault:
            objects = {}
            for ref in pinned:
                check_deadline()
                row = vault.execute("SELECT data FROM objects WHERE digest = ?", (ref,)).fetchone()
                if row is None or _digest(row["data"]) != ref:
                    raise BackupDenied("VAULT_OBJECT_MISSING_OR_CORRUPT")
                objects[ref] = row["data"]
        check_deadline()
        return Capture(database, versions, {ref: objects[ref] for ref in ciphertexts},
                       {ref: objects[ref] for ref in wrapped})

    @staticmethod
    def _finish_interrupted(db, backup_id, phase, reason):
        terminal = Phase.ABORTED if phase in _PRE_SNAPSHOT else Phase.FAILED
        db.execute("UPDATE backups SET phase = ?, reason = ? WHERE id = ?", (terminal, reason, backup_id))
        db.execute("DELETE FROM pins WHERE backup_id = ?", (backup_id,))

    def recover_interrupted(self) -> None:
        """Call only after the prior coordinator process has stopped."""
        with self._write() as db:
            row = db.execute("SELECT id, phase FROM backups WHERE phase NOT IN ('PUBLISHED', 'FAILED', 'ABORTED')").fetchone()
            if row is not None:
                self._finish_interrupted(db, row["id"], row["phase"], "INTERRUPTED")
        if row is not None:
            # A killed capture can leave a private temporary metadata directory.
            for directory in self._root.glob(f"snapshot-{row['id']}-*"):
                shutil.rmtree(directory)

    def run(
        self,
        recipient: str,
        signing_key: SigningKey,
        publish: Callable[[str, SignedBackup], str],
        *,
        observe: Callable[[str, Phase], None] | None = None,
        drain_seconds: float = 60,
        barrier_seconds: float = 30,
    ) -> str:
        """Publish via a fixture callback only after business admission has reopened."""
        if not 0 < drain_seconds <= 60 or not 0 < barrier_seconds <= 30:
            raise ValueError("Fixture deadlines may only shorten the protocol limits")
        backup_id = secrets.token_hex(16)

        def observed(phase):
            if observe is not None:
                observe(backup_id, phase)

        def advance(previous, phase):
            self._advance(backup_id, previous, phase)
            observed(phase)

        self._request(backup_id)
        try:
            observed(Phase.REQUESTED)
            self._advance(backup_id, Phase.REQUESTED, Phase.CLOSING_ADMISSION)
            drain_deadline = time.monotonic() + drain_seconds
            observed(Phase.CLOSING_ADMISSION)
            self._drain(backup_id, drain_deadline)
            barrier_deadline = time.monotonic() + barrier_seconds
            observed(Phase.SHORT_BARRIER)
            captured = self._capture(backup_id, barrier_deadline)
            advance(Phase.SHORT_BARRIER, Phase.BARRIER_RELEASED)
            sealed = encrypt_source(captured.portable(self._wrapper), recipient)
            advance(Phase.BARRIER_RELEASED, Phase.SEALED)
            signed = sealed.sign(signing_key)
            advance(Phase.SEALED, Phase.SIGNED)
            advance(Phase.SIGNED, Phase.UPLOADING)
            if publish(backup_id, signed) != signed.envelope_sha256:
                raise BackupDenied("PUBLICATION_UNVERIFIED")
        except Exception as error:
            with self._write() as db:
                row = db.execute("SELECT phase FROM backups WHERE id = ?", (backup_id,)).fetchone()
                if row["phase"] not in (Phase.ABORTED, Phase.FAILED, Phase.PUBLISHED):
                    reason = str(error) if isinstance(error, BackupDenied) else type(error).__name__
                    self._finish_interrupted(db, backup_id, row["phase"], reason)
            raise
        advance(Phase.UPLOADING, Phase.PUBLISHED)
        return backup_id
