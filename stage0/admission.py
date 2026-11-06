"""Lab model of one durable admission authority. This module performs no remote I/O."""

from collections.abc import Collection, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
import json
from pathlib import Path
import secrets
from typing import TYPE_CHECKING

from .journal import connect_journal, reserve_journal

if TYPE_CHECKING:
    from .recovery import RecoveryTarget


class ControllerMode(StrEnum):
    ACTIVE = "ACTIVE"
    READ_ONLY_RECOVERY = "READ_ONLY_RECOVERY"


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

_RECOVERY_SCHEMA = """
CREATE TABLE recovery (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    binding TEXT NOT NULL,
    owner_verify_key BLOB NOT NULL,
    attestation BLOB,
    signature BLOB,
    CHECK ((attestation IS NULL) = (signature IS NULL))
);
CREATE TABLE recovery_scope (
    host TEXT PRIMARY KEY NOT NULL REFERENCES hosts(id),
    quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1))
);
PRAGMA user_version = 2;
"""


class HostGate:
    """Open a lab journal. Only create() can initialize a new fixture."""

    def __init__(self, path: Path):
        self._path = path.absolute()

    @classmethod
    def create(
        cls, path: Path, topology: Mapping[str, Collection[str] | None],
        *, recovery: "RecoveryTarget | None" = None,
    ) -> "HostGate":
        """Create a fresh fixture journal. A restore supplies an independently anchored target."""
        if any(isinstance(resources, (str, bytes)) for resources in topology.values()):
            raise ValueError("Each host needs a collection of resource IDs")
        gate = cls(path)
        reserve_journal(gate._path)
        with gate._connect(initialize=True) as db:
            schema = _SCHEMA if recovery is None else _SCHEMA + _RECOVERY_SCHEMA
            db.executescript("BEGIN IMMEDIATE;\n" + schema)
            if recovery is not None:
                db.execute(
                    "INSERT INTO recovery VALUES (1, ?, ?, NULL, NULL)",
                    (json.dumps(recovery.binding()), recovery.owner_verify_key),
                )
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
        return connect_journal(self._path, initialize=initialize, versions=(1, 2))

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
    def _recovery(db):
        if db.execute("PRAGMA user_version").fetchone()[0] == 1:
            return None
        row = db.execute(
            "SELECT binding, owner_verify_key, attestation IS NOT NULL AS activated FROM recovery WHERE id = 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("Missing recovery target")
        return row

    def _require_active(self, db) -> bool:
        recovery = self._recovery(db)
        if recovery is not None and not recovery["activated"]:
            raise Denied("READ_ONLY_RECOVERY")
        return recovery is not None

    def _require_no_incidents(self, db):
        if db.execute("SELECT 1 FROM incidents LIMIT 1").fetchone():
            raise Denied("OPEN_INCIDENT")
        if self._recovery(db) is not None and db.execute(
            "SELECT 1 FROM recovery_scope WHERE quarantined = 1 LIMIT 1"
        ).fetchone():
            raise Denied("RECOVERY_QUARANTINE")

    @staticmethod
    def _dependency_closure(db, hosts: set[str]) -> frozenset[str]:
        if not hosts:
            return frozenset()
        if db.execute("SELECT 1 FROM hosts WHERE dependencies_known = 0").fetchone():
            raise Denied("DEPENDENCIES_UNPROVEN")
        placeholders = ",".join("?" for _ in hosts)
        rows = db.execute(
            f"""WITH RECURSIVE affected(host) AS (
                    SELECT id FROM hosts WHERE id IN ({placeholders})
                    UNION
                    SELECT peer.host FROM affected
                    JOIN dependencies AS own ON own.host = affected.host
                    JOIN dependencies AS peer ON peer.resource = own.resource
                ) SELECT host FROM affected""",
            tuple(hosts),
        )
        return frozenset(row["host"] for row in rows)

    def controller_mode(self) -> ControllerMode:
        with self._connect() as db:
            recovery = self._recovery(db)
            if recovery is not None and not recovery["activated"]:
                return ControllerMode.READ_ONLY_RECOVERY
            return ControllerMode.ACTIVE

    def activate_recovery(
        self, attestation: bytes, signature: bytes, *, owner_confirmation: str,
    ) -> frozenset[str]:
        """Local fixture activation. Store evidence and permitted scope in one commit."""
        from .recovery import verify_activation

        with self._write() as db:
            recovery = self._recovery(db)
            if recovery is None or recovery["activated"]:
                raise Denied("RECOVERY_NOT_PENDING")
            if self._gate(db)["state"] != GateState.NORMAL:
                raise Denied("GATE_CLOSED")
            hosts = {row["id"] for row in db.execute("SELECT id FROM hosts")}
            seeds = verify_activation(
                attestation, signature, owner_confirmation=owner_confirmation,
                owner_verify_key=recovery["owner_verify_key"],
                expected_binding=json.loads(recovery["binding"]), expected_hosts=hosts,
            )
            quarantined = self._dependency_closure(db, seeds)
            safe = frozenset(hosts - quarantined)
            if not safe:
                raise Denied("NO_SAFE_RECOVERY_TARGETS")
            db.executemany(
                "INSERT INTO recovery_scope VALUES (?, ?)",
                ((host, host in quarantined) for host in hosts),
            )
            db.execute("UPDATE recovery SET attestation = ?, signature = ? WHERE id = 1", (attestation, signature))
            return safe

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
            restored = self._require_active(db)
            gate = self._gate(db)
            if gate["state"] != GateState.NORMAL:
                raise Denied("GATE_CLOSED")
            if db.execute("SELECT 1 FROM hosts WHERE id = ?", (host,)).fetchone() is None:
                raise Denied("UNREGISTERED_HOST")
            if db.execute("SELECT 1 FROM incidents WHERE decision_ref IS NULL").fetchone():
                raise Denied("OPEN_INCIDENT")
            if db.execute("SELECT 1 FROM quarantine WHERE host = ?", (host,)).fetchone():
                raise Denied("QUARANTINED")
            if restored and db.execute(
                "SELECT 1 FROM recovery_scope WHERE host = ? AND quarantined = 0", (host,)
            ).fetchone() is None:
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
                """SELECT i.decision_ref, a.host FROM incidents i
                   JOIN attempts a USING (operation_id) WHERE i.operation_id = ?""", (operation_id,)
            ).fetchone()
            if incident is None:
                raise Denied("NO_OPEN_INCIDENT")
            if incident["decision_ref"] is not None:
                raise Denied("QUARANTINE_ALREADY_RECORDED")
            affected = self._dependency_closure(db, {incident["host"]})
            db.executemany(
                "INSERT INTO quarantine VALUES (?, ?)", ((operation_id, host) for host in affected),
            )
            db.execute(
                "UPDATE incidents SET decision_ref = ? WHERE operation_id = ?",
                (decision_ref, operation_id),
            )
            return affected

    def request_update(self, kind: UpdateKind) -> UpdateTicket:
        """Commit QUIESCING before returning a ticket. An active remote attempt may drain."""
        if not isinstance(kind, UpdateKind):
            raise ValueError("Unknown update kind")
        with self._write() as db:
            self._require_active(db)
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
