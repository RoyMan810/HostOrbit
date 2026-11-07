"""Rehearse the exact historical schema 1 → 2 migration on private copies only.

There is intentionally no live apply command. A rehearsal is neither a
ControllerBackup nor permission to bypass maintenance, backup or time gates.
"""

import base64
from contextlib import closing
import hashlib
from importlib.resources import files
import os
from pathlib import Path
import sqlite3
import stat
import time

from .database import SCHEMA_VERSION, Store, _SCHEMA, canonical, identifier
from .errors import Denied
from .runtime.storage import directory_sync, new_private_file


_HISTORICAL_SCHEMA_SHA256 = "825d6b23d2ac197fa0e62fd7a649ce8563ef84a5f0cdee3135817dd619894db3"
_NEW_TABLES = ("resources", "jobs", "request_keys", "job_incidents")


def historical_schema():
    data = files("hostorbit").joinpath("schema_v1.sql").read_bytes()
    if hashlib.sha256(data).hexdigest() != _HISTORICAL_SCHEMA_SHA256:
        raise Denied("HISTORICAL_SCHEMA_UNTRUSTED")
    return data.decode()


def schema_rows(db):
    return [list(row) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")]


def expected_schema(version):
    if version not in (1, 2):
        raise Denied("MIGRATION_SCHEMA_UNSUPPORTED")
    with closing(sqlite3.connect(":memory:")) as db:
        db.executescript(historical_schema() if version == 1 else _SCHEMA)
        return schema_rows(db)


def _verify(db, version):
    if SCHEMA_VERSION != 2 or db.execute("PRAGMA user_version").fetchone()[0] != version:
        raise Denied("MIGRATION_SCHEMA_UNSUPPORTED")
    if schema_rows(db) != expected_schema(version):
        raise Denied("MIGRATION_SCHEMA_DRIFT")
    if ([tuple(row) for row in db.execute("PRAGMA integrity_check")] != [("ok",)]
            or db.execute("PRAGMA foreign_key_check").fetchone() is not None):
        raise Denied("MIGRATION_SOURCE_CORRUPT")
    return Store.verify_audit_connection(db)


def _value(value):
    return {"bytes": base64.b64encode(value).decode()} if isinstance(value, bytes) else value


def _legacy_digest(db, audit_sequence):
    """Hash every historical business row, with no credential values in reports."""
    digest, counts = hashlib.sha256(), {}
    for row in expected_schema(1):
        if row[0] != "table":
            continue
        name = row[1]
        columns = [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')]
        order = ",".join('"' + column + '"' for column in columns)
        query = f'SELECT * FROM "{name}"'
        parameters = ()
        if name in ("audit", "outbox"):
            query += " WHERE seq<=?"
            parameters = (audit_sequence,)
        count = 0
        digest.update(canonical({"table": name, "columns": columns}).encode() + b"\n")
        for values in db.execute(query + " ORDER BY " + order, parameters):
            digest.update(canonical([_value(value) for value in values]).encode() + b"\n")
            count += 1
        counts[name] = count
    return digest.hexdigest(), counts


def _statements(script):
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            yield buffer
            buffer = ""
    if buffer.strip():
        raise Denied("MIGRATION_DEFINITION_INVALID")


def _migrate_snapshot(store, *, audit_sequence, legacy_digest, at, correlation, progress):
    """Internal copy executor; callers never pass the live database here."""
    with store.write() as db:
        db.set_progress_handler(progress, 1000)
        _verify(db, 1)
        if _legacy_digest(db, audit_sequence)[0] != legacy_digest:
            raise Denied("MIGRATION_SNAPSHOT_CHANGED")
        # executescript() would implicitly commit an open transaction. Execute
        # each release-defined statement so DDL, audit and version commit once.
        suffix = _SCHEMA[_SCHEMA.index("CREATE TABLE resources"):]
        for statement in _statements(suffix):
            db.execute(statement)
        seq = Store.event(db, at=at, actor="local-root", kind="database.schema_migrated",
                          target="controller", outcome="SUCCEEDED", correlation=correlation,
                          details={"from_schema": 1, "to_schema": 2, "rehearsal": True,
                                   "source_rows_sha256": legacy_digest})
        head = _verify(db, 2)
        if _legacy_digest(db, audit_sequence)[0] != legacy_digest:
            raise Denied("MIGRATION_PRESERVATION_FAILED")
        for name in _NEW_TABLES:
            if db.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]:
                raise Denied("MIGRATION_NEW_TABLE_NOT_EMPTY")
        return seq, head


def _new_copy(path):
    new_private_file(path, b"")
    return sqlite3.connect(path, autocommit=True, timeout=5)


def rehearse(store, output, *, clock=time.monotonic):
    """Read-only SQLite source + bounded, coherent copies; never replace source."""
    output = Path(output).absolute()
    for parent in output.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise Denied("MIGRATION_OUTPUT_PARENT_UNTRUSTED")
    # Exclusive directory creation also rejects an existing symlink or prior
    # output. The source and copied credentials remain inaccessible to Web UIDs.
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    directory_sync(output.parent)
    report = {"v": 1, "status": "RUNNING", "applied_to_source": False,
              "live_apply": "BLOCKED", "schema_before": 1, "schema_after": 2,
              "required_live_gates": ["OWNER_UPDATE_APPROVAL", "SIGNED_COMPATIBLE_RELEASE",
                                      "HOST_MAINTENANCE", "CONTROLLER_BACKUP", "TIME_HEALTH"]}
    new_private_file(output / "rehearsal.json", canonical(report).encode())
    end = clock() + 30

    def deadline(*_):
        if clock() >= end:
            raise Denied("MIGRATION_REHEARSAL_TIMEOUT")

    def sql_deadline():
        return int(clock() >= end)

    source_path, migrated_path = output / "source.sqlite3", output / "migrated.sqlite3"
    try:
        # mode=ro is enforced by SQLite, not a promise that a callback won't
        # accidentally write. The transaction pins WAL across both backups.
        with store.connect(readonly=True) as source:
            source.set_progress_handler(sql_deadline, 1000)
            source.execute("BEGIN")
            head_before = _verify(source, 1)
            sequence = source.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0]
            legacy_digest, counts = _legacy_digest(source, sequence)
            for destination in (source_path, migrated_path):
                deadline()
                with closing(_new_copy(destination)) as copy:
                    source.backup(copy, pages=64, progress=deadline, sleep=0.05)
                    copy.execute("PRAGMA synchronous=FULL")
            source.execute("COMMIT")
        with source_path.open("rb") as stream:
            digest = hashlib.sha256()
            while chunk := stream.read(256 * 1024):
                deadline()
                digest.update(chunk)
            snapshot_hash = digest.hexdigest()
        copied = Store(migrated_path)
        # The preservation verifier expects sqlite3.Row audit records.
        deadline()
        seq, head_after = _migrate_snapshot(copied, audit_sequence=sequence, legacy_digest=legacy_digest,
                                            at=int(time.time()), correlation=identifier(), progress=sql_deadline)
        deadline()
        # Verify again from a new connection after the durable commit.
        with copied.connect(readonly=True) as db:
            db.set_progress_handler(sql_deadline, 1000)
            _verify(db, 2)
            if _legacy_digest(db, sequence)[0] != legacy_digest:
                raise Denied("MIGRATION_PRESERVATION_FAILED")
        report.update(status="REHEARSAL_PASSED", source_snapshot_sha256=snapshot_hash,
                      source_rows_sha256=legacy_digest, source_audit_sequence=sequence,
                      source_audit_head=head_before, migrated_audit_sequence=seq,
                      migrated_audit_head=head_after, preserved_table_rows=counts)
    except BaseException:
        # SIGKILL may leave RUNNING. Never advertise a partial copy as passed,
        # never substitute it for the live database and never auto-downgrade.
        report["status"] = "FAILED"
        raise
    finally:
        # A missing success report is a failed rehearsal. Only this private
        # output is replaced; the source path is never passed to os.replace.
        temporary = output / "rehearsal.complete.json"
        new_private_file(temporary, canonical(report).encode())
        os.replace(temporary, output / "rehearsal.json")
        directory_sync(output)
    return report
