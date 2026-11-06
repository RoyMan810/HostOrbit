"""SQLite settings shared by the local Stage 0 journals."""

from contextlib import closing, contextmanager
import os
from pathlib import Path
import sqlite3


def reserve_journal(path: Path) -> None:
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))


@contextmanager
def connect_journal(path: Path, *, initialize=False, versions=(1,)):
    if sqlite3.sqlite_version_info < (3, 45, 0):
        raise RuntimeError("SQLite 3.45 or newer is required")
    uri = f"{path.absolute().as_uri()}?mode=rw"
    with closing(sqlite3.connect(uri, uri=True, autocommit=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA foreign_keys = ON")
        if initialize:
            db.execute("PRAGMA journal_mode = WAL").fetchone()
        expected = {
            "journal_mode": "wal",
            "synchronous": 2,
            "foreign_keys": 1,
            "busy_timeout": 5000,
        }
        for pragma, value in expected.items():
            if db.execute(f"PRAGMA {pragma}").fetchone()[0] != value:
                raise RuntimeError(f"Unexpected SQLite setting: {pragma}")
        if db.execute("PRAGMA user_version").fetchone()[0] not in ((0,) if initialize else versions):
            raise RuntimeError("Unexpected SQLite setting: user_version")
        try:
            yield db
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
