"""Explicitly initialized application SQLite, audit chain and transactional outbox."""

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time


SCHEMA_VERSION = 1
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_SCHEMA = """
CREATE TABLE users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, password_profile INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Owner','Admin','Operator','Auditor')),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE grants (
    user_id TEXT NOT NULL REFERENCES users(id), permission TEXT NOT NULL,
    resource_id TEXT NOT NULL, PRIMARY KEY(user_id, permission, resource_id)
);
CREATE TABLE sessions (
    digest BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
    csrf_digest BLOB NOT NULL, issued_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE bootstrap (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest BLOB NOT NULL,
    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY, account TEXT NOT NULL, ip TEXT NOT NULL,
    at INTEGER NOT NULL, failed INTEGER NOT NULL CHECK(failed IN (0,1))
);
CREATE INDEX login_ip_time ON login_attempts(ip, at);
CREATE INDEX login_account_ip_time ON login_attempts(account, ip, at);
CREATE TABLE login_requests (ip TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX login_requests_ip_time ON login_requests(ip, at);
CREATE TABLE api_calls (user_id TEXT NOT NULL, ip TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX api_user_time ON api_calls(user_id, at);
CREATE INDEX api_ip_time ON api_calls(ip, at);
CREATE TABLE critical_attempts (user_id TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX critical_user_time ON critical_attempts(user_id, at);
CREATE TABLE reauth (
    id TEXT PRIMARY KEY, session_digest BLOB NOT NULL REFERENCES sessions(digest) ON DELETE CASCADE,
    plan_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
    at INTEGER NOT NULL, actor_id TEXT NOT NULL, event TEXT NOT NULL,
    target_id TEXT NOT NULL, outcome TEXT NOT NULL, correlation_id TEXT NOT NULL,
    details TEXT NOT NULL, previous_hash TEXT NOT NULL, digest TEXT NOT NULL
);
CREATE INDEX audit_target_time ON audit(target_id, at);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
CREATE TABLE outbox (
    seq INTEGER PRIMARY KEY REFERENCES audit(seq), event_id TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TRIGGER outbox_no_update BEFORE UPDATE ON outbox BEGIN SELECT RAISE(ABORT,'OUTBOX_APPEND_ONLY'); END;
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox BEGIN SELECT RAISE(ABORT,'OUTBOX_APPEND_ONLY'); END;
PRAGMA user_version = 1;
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def identifier():
    number = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    return "".join(_ALPHABET[(number >> shift) & 31] for shift in range(125, -1, -5))


class Store:
    def __init__(self, path: Path):
        self.path = Path(path).absolute()

    def _permissions(self):
        parent = self.path.parent.stat()
        file = self.path.lstat()
        if (parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077
                or not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(file.st_mode)
                or file.st_uid != os.geteuid() or stat.S_IMODE(file.st_mode) != 0o600):
            raise RuntimeError("DATABASE_PERMISSIONS")

    @classmethod
    def initialize(cls, path: Path):
        store = cls(path)
        store.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent = store.path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise RuntimeError("DATABASE_DIRECTORY_PERMISSIONS")
        os.close(os.open(store.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
        with store.connect(initializing=True) as db:
            db.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            db.execute("COMMIT")
        return store

    @contextmanager
    def connect(self, *, initializing=False):
        self._permissions()
        if sqlite3.sqlite_version_info < (3, 45):
            raise RuntimeError("SQLITE_VERSION_UNSUPPORTED")
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, autocommit=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            if initializing:
                db.execute("PRAGMA journal_mode=WAL")
            for name, expected in {"journal_mode": "wal", "synchronous": 2, "foreign_keys": 1, "busy_timeout": 5000,
                                   "user_version": 0 if initializing else SCHEMA_VERSION}.items():
                if db.execute(f"PRAGMA {name}").fetchone()[0] != expected:
                    raise RuntimeError("DATABASE_CONTRACT_MISMATCH")
            try:
                yield db
            finally:
                if db.in_transaction:
                    db.execute("ROLLBACK")

    @contextmanager
    def write(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")

    @contextmanager
    def read(self):
        with self.connect() as db:
            db.execute("BEGIN")
            yield db
            db.execute("COMMIT")

    @staticmethod
    def event(db, *, at, actor, kind, target, outcome, correlation, details=None):
        previous = db.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        value = dict(id=identifier(), at=at, actor_id=actor, event=kind, target_id=target,
                     outcome=outcome, correlation_id=correlation, details=details or {}, previous_hash=previous)
        digest = hashlib.sha256(canonical(value).encode()).hexdigest()
        cursor = db.execute(
            """INSERT INTO audit(id, at, actor_id, event, target_id, outcome, correlation_id, details, previous_hash, digest)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (value["id"], at, actor, kind, target, outcome, correlation, canonical(value["details"]), previous, digest),
        )
        db.execute("INSERT INTO outbox VALUES(?,?,?,?)", (cursor.lastrowid, value["id"], canonical({**value, "digest": digest}), at))
        return cursor.lastrowid

    def events_after(self, after: int, *, limit=100):
        with self.connect() as db:
            return [dict(seq=row["seq"], event=json.loads(row["payload"])) for row in db.execute(
                "SELECT seq,payload FROM outbox WHERE seq>? ORDER BY seq LIMIT ?", (after, min(limit, 100)),
            )]

    def verify_audit(self):
        with self.read() as db:
            previous = "0" * 64
            for row in db.execute("SELECT * FROM audit ORDER BY seq"):
                value = {key: row[key] for key in ("id", "at", "actor_id", "event", "target_id", "outcome", "correlation_id", "previous_hash")}
                value["details"] = json.loads(row["details"])
                if value["previous_hash"] != previous or hashlib.sha256(canonical(value).encode()).hexdigest() != row["digest"]:
                    raise RuntimeError("AUDIT_INTEGRITY")
                outbox = db.execute("SELECT payload FROM outbox WHERE seq=?", (row["seq"],)).fetchone()
                if outbox is None or outbox[0] != canonical({**value, "digest": row["digest"]}):
                    raise RuntimeError("OUTBOX_INTEGRITY")
                previous = row["digest"]
            return previous
