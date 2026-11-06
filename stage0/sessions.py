"""Lab checks for durable server-side sessions and per-session CSRF tokens."""

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
from pathlib import Path
import secrets
import time

from .journal import connect_journal, reserve_journal


_IDLE_SECONDS = 30 * 60
_ABSOLUTE_SECONDS = 12 * 60 * 60

_SCHEMA = """
CREATE TABLE principals (
    id TEXT PRIMARY KEY NOT NULL,
    role TEXT NOT NULL
);
CREATE TABLE sessions (
    token_digest BLOB PRIMARY KEY NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(id),
    csrf_digest BLOB NOT NULL,
    issued_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX sessions_by_principal ON sessions (principal_id);
PRAGMA user_version = 1;
"""


class Role(StrEnum):
    OWNER = "Owner"
    ADMIN = "Admin"
    OPERATOR = "Operator"
    AUDITOR = "Auditor"


class SessionDenied(RuntimeError):
    """The session or its CSRF token failed validation."""


@dataclass(frozen=True)
class Credentials:
    session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True)
class Principal:
    id: str
    role: Role


def _digest(token: str | None) -> bytes | None:
    # token_urlsafe(32) emits 43 ASCII characters.
    if not isinstance(token, str) or len(token) != 43 or not token.isascii():
        return None
    return hashlib.sha256(token.encode("ascii")).digest()


class SessionLab:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time):
        self._path = path.absolute()
        self._clock = clock

    @classmethod
    def create(
        cls, path: Path, principals: Mapping[str, Role], *, clock: Callable[[], float] = time.time,
    ) -> "SessionLab":
        lab = cls(path, clock=clock)
        roles = [(principal_id, Role(role)) for principal_id, role in principals.items()]
        reserve_journal(lab._path)
        with connect_journal(lab._path, initialize=True) as db:
            db.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            db.executemany("INSERT INTO principals VALUES (?, ?)", roles)
            db.execute("COMMIT")
        return lab

    @contextmanager
    def _write(self):
        with connect_journal(self._path) as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")

    def issue_after_authentication(self, principal_id: str, *, previous_token: str | None = None) -> Credentials:
        """Accept a trusted lab authentication and rotate a presented session for that principal."""
        tokens = Credentials(secrets.token_urlsafe(32), secrets.token_urlsafe(32))
        with self._write() as db:
            now = int(self._clock())
            db.execute(
                "DELETE FROM sessions WHERE principal_id = ? AND token_digest = ?",
                (principal_id, _digest(previous_token)),
            )
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                (_digest(tokens.session_token), principal_id, _digest(tokens.csrf_token), now, now),
            )
        return tokens

    def authenticate_request(
        self, session_token: str | None, *, mutating: bool, csrf_token: str | None = None,
    ) -> Principal:
        """Validate the session for a request and return its current principal for RBAC."""
        return self._check(session_token, mutating=mutating, csrf_token=csrf_token, logout=False)

    def logout(self, session_token: str | None, *, csrf_token: str | None) -> None:
        self._check(session_token, mutating=True, csrf_token=csrf_token, logout=True)

    def _check(
        self, session_token: str | None, *, mutating: bool, csrf_token: str | None, logout: bool,
    ) -> Principal:
        digest = _digest(session_token)
        if digest is None:
            raise SessionDenied("SESSION_REQUIRED")
        with self._write() as db:
            now = int(self._clock())
            row = db.execute(
                """SELECT p.id, p.role, s.csrf_digest FROM sessions s
                   JOIN principals p ON p.id = s.principal_id
                   WHERE s.token_digest = ? AND s.last_seen <= ?
                     AND s.last_seen > ? AND s.issued_at > ?""",
                (digest, now, now - _IDLE_SECONDS, now - _ABSOLUTE_SECONDS),
            ).fetchone()
            if row is not None and mutating:
                submitted = _digest(csrf_token)
                if submitted is None or not secrets.compare_digest(submitted, row["csrf_digest"]):
                    raise SessionDenied("CSRF_REQUIRED")
            if row is None or logout:
                db.execute("DELETE FROM sessions WHERE token_digest = ?", (digest,))
            else:
                db.execute("UPDATE sessions SET last_seen = ? WHERE token_digest = ?", (now, digest))
        if row is None:
            raise SessionDenied("SESSION_REQUIRED")
        return Principal(row["id"], Role(row["role"]))

    def revoke_sessions(self, principal_id: str) -> None:
        with self._write() as db:
            db.execute("DELETE FROM sessions WHERE principal_id = ?", (principal_id,))

    def change_role(self, principal_id: str, role: Role) -> None:
        role = Role(role)
        with self._write() as db:
            changed = db.execute(
                "UPDATE principals SET role = ? WHERE id = ? AND role <> ?",
                (role, principal_id, role),
            )
            if changed.rowcount:
                db.execute("DELETE FROM sessions WHERE principal_id = ?", (principal_id,))
