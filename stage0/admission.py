"""Lab model of one durable admission authority. This module performs no remote I/O."""

from collections.abc import Collection, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import secrets

from .journal import connect_journal, reserve_journal


class GateState(StrEnum):
    NORMAL = "NORMAL"
    QUIESCING = "QUIESCING"
    MAINTENANCE = "MAINTENANCE"
    RESUMING = "RESUMING"
    RECOVERY_HOLD = "RECOVERY_HOLD"


class UpdateKind(StrEnum):
    APPLICATION = "application"
    SELF = "self"


class Outcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    UNKNOWN = "UNKNOWN_OUTCOME"


class Denied(RuntimeError):
    """The fixture was denied permission to act."""


@dataclass(frozen=True)
class RemotePermit:
    operation_id: str
    host: str
    epoch: int
    nonce: str


@dataclass(frozen=True)
class UpdateTicket:
    kind: UpdateKind
    epoch: int
    nonce: str


@dataclass(frozen=True)
class FixtureObservation:
    direct_stopped: bool
    delegated_terminal: bool
    postcondition_verified: bool


_SCHEMA = """
CREATE TABLE gate (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    update_kind TEXT,
    update_nonce TEXT
);
INSERT INTO gate VALUES (1, 'NORMAL', 0, NULL, NULL);
CREATE TABLE hosts (
    id TEXT PRIMARY KEY NOT NULL,
    dependencies_known INTEGER NOT NULL
);
CREATE TABLE dependencies (
    host TEXT NOT NULL REFERENCES hosts(id),
    resource TEXT NOT NULL,
    PRIMARY KEY (host, resource)
);
CREATE TABLE attempts (
    operation_id TEXT PRIMARY KEY NOT NULL,
    host TEXT NOT NULL REFERENCES hosts(id),
    epoch INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    outcome TEXT
);
CREATE UNIQUE INDEX one_remote_permit ON attempts ((1)) WHERE outcome IS NULL;
CREATE TABLE incidents (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES attempts(operation_id),
    decision_ref TEXT
);
CREATE TABLE quarantine (
    operation_id TEXT NOT NULL REFERENCES incidents(operation_id),
    host TEXT NOT NULL REFERENCES hosts(id),
    PRIMARY KEY (operation_id, host)
);
PRAGMA user_version = 1;
"""


class HostGate:
    """Open a lab journal. Only create() can initialize a new fixture."""

    def __init__(self, path: Path):
        self._path = path.absolute()

    @classmethod
    def create(cls, path: Path, topology: Mapping[str, Collection[str] | None]) -> "HostGate":
        """Persist fixed host dependencies. None marks an incomplete host inventory."""
        if any(isinstance(resources, (str, bytes)) for resources in topology.values()):
            raise ValueError("Each host needs a collection of resource IDs")
        gate = cls(path)
        reserve_journal(gate._path)
        with gate._connect(initialize=True) as db:
            db.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            db.executemany(
                "INSERT INTO hosts VALUES (?, ?)",
                ((host, resources is not None) for host, resources in topology.items()),
            )
            db.executemany(
                "INSERT INTO dependencies VALUES (?, ?)",
                (
                    (host, resource)
                    for host, resources in topology.items()
                    for resource in set(resources or ())
                ),
            )
            db.execute("COMMIT")
        return gate

    def _connect(self, *, initialize=False):
        return connect_journal(self._path, initialize=initialize)

    @contextmanager
    def _write(self):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")

    @staticmethod
    def _gate(db):
        row = db.execute("SELECT * FROM gate WHERE id = 1").fetchone()
        if row is None:
            raise RuntimeError("Missing gate state")
        return row

    @staticmethod
    def _require_no_incidents(db):
        if db.execute("SELECT 1 FROM incidents LIMIT 1").fetchone():
            raise Denied("OPEN_INCIDENT")

    @staticmethod
    def _hold(db):
        db.execute(
            """UPDATE gate SET state = ?, epoch = epoch + 1,
               update_kind = NULL, update_nonce = NULL WHERE id = 1""",
            (GateState.RECOVERY_HOLD,),
        )

    def state(self) -> GateState:
        with self._connect() as db:
            return GateState(self._gate(db)["state"])

    def outcome(self, operation_id: str) -> Outcome | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT outcome FROM attempts WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if row is None:
                raise KeyError(operation_id)
            return Outcome(row["outcome"]) if row["outcome"] else None

    def admit_remote(self, host: str, operation_id: str) -> RemotePermit:
        """Commit an exclusive, one-shot attempt before the fixture could dispatch it."""
        if not operation_id.strip():
            raise ValueError("An operation ID is required")
        with self._write() as db:
            gate = self._gate(db)
            if gate["state"] != GateState.NORMAL:
                raise Denied("GATE_CLOSED")
            if db.execute("SELECT 1 FROM hosts WHERE id = ?", (host,)).fetchone() is None:
                raise Denied("UNREGISTERED_HOST")
            if db.execute("SELECT 1 FROM incidents WHERE decision_ref IS NULL").fetchone():
                raise Denied("OPEN_INCIDENT")
            if db.execute("SELECT 1 FROM quarantine WHERE host = ?", (host,)).fetchone():
                raise Denied("QUARANTINED")
            if db.execute(
                "SELECT 1 FROM attempts WHERE operation_id = ?", (operation_id,)
            ).fetchone():
                raise Denied("OPERATION_ALREADY_ADMITTED")
            if db.execute("SELECT 1 FROM attempts WHERE outcome IS NULL").fetchone():
                raise Denied("REMOTE_PERMIT_HELD")
            permit = RemotePermit(operation_id, host, gate["epoch"], secrets.token_hex(16))
            db.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?, NULL)",
                (permit.operation_id, permit.host, permit.epoch, permit.nonce),
            )
            return permit

    @staticmethod
    def _record_unknown(db, operation_id):
        db.execute(
            "UPDATE attempts SET outcome = ? WHERE operation_id = ?",
            (Outcome.UNKNOWN, operation_id),
        )
        db.execute("INSERT INTO incidents VALUES (?, NULL)", (operation_id,))

    def report_remote(self, permit: RemotePermit, observation: FixtureObservation) -> Outcome:
        """Accept only a current permit; fixture process exit alone keeps an incident open."""
        with self._write() as db:
            row = db.execute(
                """SELECT 1 FROM attempts WHERE operation_id = ? AND host = ?
                   AND epoch = ? AND nonce = ? AND outcome IS NULL""",
                (permit.operation_id, permit.host, permit.epoch, permit.nonce),
            ).fetchone()
            if row is None:
                raise Denied("INVALID_REMOTE_PERMIT")
            if (
                observation.direct_stopped
                and observation.delegated_terminal
                and observation.postcondition_verified
            ):
                db.execute(
                    "UPDATE attempts SET outcome = ? WHERE operation_id = ?",
                    (Outcome.SUCCEEDED, permit.operation_id),
                )
                return Outcome.SUCCEEDED
            self._record_unknown(db, permit.operation_id)
            if self._gate(db)["state"] == GateState.QUIESCING:
                self._hold(db)
            return Outcome.UNKNOWN

    def record_quarantine(self, operation_id: str, *, decision_ref: str) -> frozenset[str]:
        """Record a fixture Owner decision without closing the underlying incident."""
        if not decision_ref.strip():
            raise ValueError("An Owner decision reference is required")
        with self._write() as db:
            incident = db.execute(
                "SELECT decision_ref FROM incidents WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if incident is None:
                raise Denied("NO_OPEN_INCIDENT")
            if incident["decision_ref"] is not None:
                raise Denied("QUARANTINE_ALREADY_RECORDED")
            if db.execute("SELECT 1 FROM hosts WHERE dependencies_known = 0").fetchone():
                raise Denied("DEPENDENCIES_UNPROVEN")
            db.execute(
                """WITH RECURSIVE affected(host) AS (
                       SELECT host FROM attempts WHERE operation_id = ?
                       UNION
                       SELECT peer.host FROM affected
                       JOIN dependencies AS own ON own.host = affected.host
                       JOIN dependencies AS peer ON peer.resource = own.resource
                   )
                   INSERT INTO quarantine SELECT ?, host FROM affected""",
                (operation_id, operation_id),
            )
            db.execute(
                "UPDATE incidents SET decision_ref = ? WHERE operation_id = ?",
                (decision_ref, operation_id),
            )
            return frozenset(
                row["host"]
                for row in db.execute(
                    "SELECT host FROM quarantine WHERE operation_id = ?", (operation_id,)
                )
            )

    def request_update(self, kind: UpdateKind) -> UpdateTicket:
        """Commit QUIESCING before returning a ticket. An active remote attempt may drain."""
        if not isinstance(kind, UpdateKind):
            raise ValueError("Unknown update kind")
        with self._write() as db:
            gate = self._gate(db)
            if gate["state"] != GateState.NORMAL:
                raise Denied("GATE_CLOSED")
            self._require_no_incidents(db)
            ticket = UpdateTicket(kind, gate["epoch"] + 1, secrets.token_hex(16))
            db.execute(
                "UPDATE gate SET state = ?, epoch = ?, update_kind = ?, update_nonce = ? WHERE id = 1",
                (GateState.QUIESCING, ticket.epoch, ticket.kind, ticket.nonce),
            )
            return ticket

    def enter_maintenance(self, ticket: UpdateTicket) -> None:
        self._advance_update(ticket, GateState.QUIESCING, GateState.MAINTENANCE)

    def begin_resume(self, ticket: UpdateTicket) -> None:
        self._advance_update(ticket, GateState.MAINTENANCE, GateState.RESUMING)

    def complete_resume(self, ticket: UpdateTicket) -> None:
        self._advance_update(ticket, GateState.RESUMING, GateState.NORMAL)

    def _advance_update(self, ticket, expected, target):
        with self._write() as db:
            gate = self._gate(db)
            if (
                gate["state"] != expected
                or gate["epoch"] != ticket.epoch
                or gate["update_kind"] != ticket.kind
                or gate["update_nonce"] != ticket.nonce
            ):
                raise Denied("INVALID_UPDATE_TICKET")
            if expected == GateState.QUIESCING:
                self._require_no_incidents(db)
                if db.execute("SELECT 1 FROM attempts WHERE outcome IS NULL").fetchone():
                    raise Denied("REMOTE_PERMIT_HELD")
            if target == GateState.NORMAL:
                db.execute(
                    "UPDATE gate SET state = ?, update_kind = NULL, update_nonce = NULL WHERE id = 1",
                    (target,),
                )
            else:
                db.execute("UPDATE gate SET state = ? WHERE id = 1", (target,))

    def recover_after_restart(self) -> GateState:
        """Run once after verified process loss, before the fixture accepts new requests."""
        with self._write() as db:
            previous = GateState(self._gate(db)["state"])
            attempt = db.execute(
                "SELECT operation_id FROM attempts WHERE outcome IS NULL"
            ).fetchone()
            if attempt is not None:
                self._record_unknown(db, attempt["operation_id"])
            if previous == GateState.NORMAL and attempt is None:
                return previous
            if previous != GateState.RECOVERY_HOLD:
                self._hold(db)
            return GateState.RECOVERY_HOLD
