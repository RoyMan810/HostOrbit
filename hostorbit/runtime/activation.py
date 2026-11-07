"""Local Owner activation of a restored Controller, with durable quarantine.

Manual isolation/remote-effect evidence is an explicit Owner trust boundary,
not an automatically verified hoster action or proof against hidden clones.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from argon2 import PasswordHasher, extract_parameters, Type
from argon2.exceptions import InvalidHashError, VerificationError
from nacl.signing import SigningKey

from ..admission import Admission
from ..database import DataAccess, Store, identifier
from ..errors import Denied
from .archive_stream import parse_manifest
from .coordinator import _deadline
from .policy import Policy
from .protocol import SHA256, ULID, canonical, checksum, fields, integer, text
from .rescue import ENV, harden
from .storage import Journal, directory_sync, new_private_file, process_lock, protected_bytes


_SCHEMA = """
CREATE TABLE plans(id TEXT PRIMARY KEY, phase TEXT NOT NULL, packet BLOB NOT NULL, reason TEXT, failures INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL REFERENCES plans(id), phase TEXT NOT NULL);
"""
_UNITS = ("hostorbit-compose.service", "hostorbit-broker.socket", "hostorbit-supervisor.socket",
          "hostorbit-broker.service", "hostorbit-supervisor.service")


def services(action):
    units = _UNITS if action == "stop" else ("hostorbit-supervisor.socket", "hostorbit-broker.socket",
                                            "hostorbit-supervisor.service", "hostorbit-broker.service", "hostorbit-compose.service")
    result = subprocess.run(["/usr/bin/systemctl", action, *units], capture_output=True, timeout=90, env=ENV)
    if result.returncode:
        raise Denied("ACTIVATION_SERVICES_UNAVAILABLE")


def broker_facts(config, candidate):
    result = subprocess.run(["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        "--property=User=" + str(config["broker_uid"]), "--property=Group=" + str(config["broker_gid"]),
        "--property=LoadCredentialEncrypted=broker-dek:" + config["vault_credential"],
        "--property=LimitCORE=0", "--property=UMask=0077", "--property=RuntimeMaxSec=20s",
        "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=PrivateNetwork=yes",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=ReadWritePaths=" + config["vault_directory"],
        "/opt/hostorbit/venv/bin/hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json", "recovery-key-facts"],
        input=canonical({"v": 1, "targets": [candidate.targets[k].value for k in sorted(candidate.targets)]}),
        capture_output=True, timeout=25, env=ENV)
    if result.returncode or len(result.stdout) > 16384:
        raise Denied("ACTIVATION_KEY_VERIFICATION_FAILED")
    return parse_manifest(canonical(json.loads(result.stdout)))


def isolation_report(value, binding, old, candidate, facts, incident_targets, now):
    fields(value, ("v", "type", "source_instance", "target_instance", "source_backup_hash", "isolation", "targets", "dependencies_reviewed"))
    if (type(value["v"]) is not int or value["v"] != 1 or value["type"] != "hostorbit.manual-isolation"
            or value["source_instance"] != binding["source_instance"] or value["target_instance"] != binding["target_id"]
            or value["source_backup_hash"] != binding["source_backup_hash"] or value["dependencies_reviewed"] is not True):
        raise Denied("ACTIVATION_REPORT_BINDING_INVALID")
    isolation = fields(value["isolation"], ("method", "console", "operator", "old_host_key", "worker_stopped", "scheduler_stopped",
        "autostart_blocked", "old_permissions_revoked", "dangerous_operations_stopped", "observations"))
    if isolation["method"] not in {"verified_local_stop", "power_off", "network_isolation"}:
        raise Denied("ISOLATION_EVIDENCE_REQUIRED")
    for name in ("console", "operator"):
        text(isolation[name], r"[^\x00-\x1f]{1,256}", "ISOLATION_EVIDENCE_REQUIRED")
    text(isolation["old_host_key"], r"SHA256:[A-Za-z0-9+/]{43}", "ISOLATION_EVIDENCE_REQUIRED")
    if isolation["old_host_key"] != binding["old_host_key"]:
        raise Denied("ACTIVATION_SOURCE_HOST_KEY_CHANGED")
    if any(isolation[k] is not True for k in ("worker_stopped", "scheduler_stopped", "autostart_blocked", "old_permissions_revoked", "dangerous_operations_stopped")):
        raise Denied("ISOLATION_EVIDENCE_REQUIRED")
    samples = isolation["observations"]
    if not isinstance(samples, list) or not 2 <= len(samples) <= 10:
        raise Denied("ISOLATION_OBSERVATIONS_REQUIRED")
    for sample in samples:
        fields(sample, ("source", "at_utc", "isolated"))
        text(sample["source"], r"[^\x00-\x1f]{1,256}", "ISOLATION_OBSERVATIONS_REQUIRED")
        integer(sample["at_utc"], now - 86400, now)
        if sample["isolated"] is not True:
            raise Denied("ISOLATION_OBSERVATIONS_REQUIRED")
    if not any(a["source"] != b["source"] and abs(a["at_utc"] - b["at_utc"]) >= 10 for a in samples for b in samples):
        raise Denied("ISOLATION_OBSERVATIONS_REQUIRED")
    reports = value["targets"]
    if not isinstance(reports, dict) or set(reports) != set(old.targets) or set(candidate.targets) != set(old.targets):
        raise Denied("ACTIVATION_INVENTORY_INCOMPLETE")
    quarantined = set(incident_targets)
    if not quarantined.issubset(old.targets):
        quarantined = set(old.targets)  # Unknown cross-host incident scope cannot establish independence.
    for identity, report in reports.items():
        if report.keys() == {"reachable", "evidence"} and report["reachable"] is False:
            quarantined.add(identity)
        else:
            fields(report, ("reachable", "evidence", "credentials_rotated", "old_key_denied", "new_key_verified", "old_key_sha256",
                           "new_key_sha256", "direct_stopped", "delegated_terminal", "postconditions_verified"))
            if any(report[k] is not True for k in ("reachable", "credentials_rotated", "old_key_denied", "new_key_verified")):
                raise Denied("ACTIVATION_CREDENTIAL_EVIDENCE_REQUIRED")
            if identity not in facts or any(report[k] != facts[identity][k] for k in ("old_key_sha256", "new_key_sha256")):
                raise Denied("ACTIVATION_CREDENTIAL_EVIDENCE_REQUIRED")
            for name in ("direct_stopped", "delegated_terminal", "postconditions_verified"):
                if type(report[name]) is not bool:
                    raise Denied("ACTIVATION_EFFECT_EVIDENCE_REQUIRED")
                if not report[name]:
                    quarantined.add(identity)
        text(report["evidence"], r"[^\x00-\x1f]{1,256}", "ACTIVATION_EFFECT_EVIDENCE_REQUIRED")
    for identity in list(quarantined):
        quarantined.update(old.closure(identity))
    for identity in set(old.targets) - quarantined:
        if identity not in facts:
            raise Denied("ACTIVATION_CREDENTIAL_EVIDENCE_REQUIRED")
    return sorted(set(old.targets) - quarantined), sorted(quarantined)


def atomic(path, data, mode=0o600):
    path = Path(path)
    temporary = path.parent / (".activate-" + os.urandom(16).hex())
    new_private_file(temporary, data)
    temporary.chmod(mode)
    os.replace(temporary, path)
    directory_sync(path.parent)


class Activation:
    def __init__(self, config, binding, *, owner=0, inspect_keys=None, manage_services=services, observe=lambda _: None):
        if os.geteuid() != owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        harden()
        self.config, self.binding, self.owner = config, binding, owner
        self.inspect_keys = inspect_keys or (lambda p: broker_facts(config, p))
        self.services, self.observe = manage_services, observe
        self.directory = Path(config["supervisor_directory"])
        self.writers = Admission(config["writer_directory"], owner=owner)
        self.store = Store(config["database"], access=DataAccess(config["app_uid"], config["app_gid"]), writers=self.writers)
        self.gate = Journal(self.directory / "gate.sqlite3")
        self.policy = Policy.load(config["targets"], owner=owner)
        self.key = SigningKey(protected_bytes(self.directory / "signing.key", owner=owner, maximum=32, exact_mode=0o600))
        self.manager = self.directory / "activation"
        if not self.manager.exists():
            self.manager.mkdir(mode=0o700)
            Journal.initialize(self.manager / "manager.sqlite3", _SCHEMA)
        self.journal = Journal(self.manager / "manager.sqlite3")

    def baseline(self):
        if (Path(self.config["writer_directory"]) / "activation.pending").exists():
            raise Denied("ACTIVATION_RECOVERY_BLOCKED")
        if self.writers.state()["phase"] != "READ_ONLY_RECOVERY":
            raise Denied("ACTIVATION_REQUIRES_READ_ONLY_RECOVERY")
        if Policy.load(self.config["targets"], owner=self.owner).digest != self.policy.digest:
            raise Denied("ACTIVATION_BASELINE_CHANGED")
        with self.gate.connect() as db:
            gate = dict(db.execute("SELECT * FROM gate WHERE id=1").fetchone())
            if (gate["activated"] != 0 or gate["state"] != "RECOVERY_HOLD" or gate["instance_id"] != self.binding["target_id"]
                    or gate["policy_digest"] != self.policy.digest or db.execute("SELECT 1 FROM attempts").fetchone()):
                raise Denied("ACTIVATION_BASELINE_INVALID")
        with self.store.read() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                raise Denied("ACTIVATION_SCHEMA_MIGRATION_REQUIRED")
            self.store.verify_audit_connection(db)
            if db.execute("SELECT 1 FROM jobs WHERE status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')").fetchone():
                raise Denied("ACTIVATION_AUTOMATION_NOT_DISABLED")
            incidents = [r[0] for r in db.execute("SELECT j.resource_id FROM job_incidents i JOIN jobs j ON j.id=i.job_id")]
        return gate, sorted(set(incidents))

    def phase(self, identity, phase, reason=None):
        with self.journal.write() as db:
            db.execute("UPDATE plans SET phase=?,reason=? WHERE id=?", (phase, reason, identity))
            db.execute("INSERT INTO events(id,phase) VALUES(?,?)", (identity, phase))
        self.observe(phase)

    def prepare(self, report, candidate):
        gate, incidents = self.baseline()
        facts = self.inspect_keys(candidate)
        allowed, quarantined = isolation_report(report, self.binding, self.policy, candidate, facts, incidents, int(time.time()))
        identity = identifier()
        packet = {"v": 1, "id": identity, "binding": self.binding, "epoch": gate["epoch"], "old_policy_digest": self.policy.digest,
                  "policy": {"v": 1, "targets": [candidate.targets[k].value for k in sorted(candidate.targets)]}, "facts": facts,
                  "report": report, "report_sha256": checksum(report), "allowed_targets": allowed, "quarantined_targets": quarantined,
                  "incident_targets": incidents, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                  "deadline_ns": time.monotonic_ns() + 900 * 10**9}
        with self.journal.write() as db:
            db.execute("INSERT INTO plans(id,phase,packet) VALUES(?,'PREPARED',?)", (identity, canonical(packet)))
            db.execute("INSERT INTO events(id,phase) VALUES(?,'PREPARED')", (identity,))
        return {"plan_id": identity, "confirmation_sha256": checksum(packet), "report_sha256": checksum(report),
                "allowed_targets": allowed, "quarantined_targets": quarantined, "confirmation": "LOCAL_OWNER_REQUIRED", "backup_gate": "DENIED"}

    def authenticate(self, username, password):
        with self.store.read() as db:
            row = db.execute("SELECT id,password_hash,revision FROM users WHERE username=? AND role='Owner' AND disabled=0", (username,)).fetchone()
        try:
            if row is None or not isinstance(password, str) or not 1 <= len(password) <= 1024:
                raise ValueError()
            parameters = extract_parameters(row["password_hash"])
            if (parameters.type != Type.ID or parameters.version != 19 or parameters.memory_cost != 65536 or parameters.time_cost != 3
                    or parameters.parallelism != 4 or parameters.hash_len != 32 or parameters.salt_len != 16):
                raise ValueError()
            PasswordHasher().verify(row["password_hash"], password)
        except (ValueError, InvalidHashError, VerificationError):
            raise Denied("ACTIVATION_OWNER_AUTH_REQUIRED") from None
        return row

    def activate(self, identity, confirmation, username, password):
        text(identity, ULID)
        text(confirmation, SHA256, "ACTIVATION_CONFIRMATION_REQUIRED")
        with process_lock(self.manager / "manager.lock"):
            with self.journal.connect() as db:
                row = db.execute("SELECT * FROM plans WHERE id=?", (identity,)).fetchone()
            if row is None or row["phase"] != "PREPARED":
                raise Denied("ACTIVATION_PLAN_CONSUMED")
            if row["failures"] >= 5:
                raise Denied("ACTIVATION_OWNER_AUTH_LOCKED")
            packet = parse_manifest(row["packet"])
            if checksum(packet) != confirmation:
                raise Denied("ACTIVATION_CONFIRMATION_REQUIRED")
            if (packet["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                    or time.monotonic_ns() >= packet["deadline_ns"] or packet["binding"] != self.binding):
                raise Denied("ACTIVATION_PLAN_EXPIRED")
            try:
                actor = self.authenticate(username, password)
            except Denied:
                with self.journal.write() as db:
                    db.execute("UPDATE plans SET failures=failures+1 WHERE id=?", (identity,))
                raise
            gate, incidents = self.baseline()
            candidate = Policy(packet["policy"]["targets"])
            if (gate["epoch"] != packet["epoch"] or self.policy.digest != packet["old_policy_digest"]
                    or incidents != packet["incident_targets"] or self.inspect_keys(candidate) != packet["facts"]):
                raise Denied("ACTIVATION_BASELINE_CHANGED")
            self.phase(identity, "CONFIRMED")  # Consumed before stopping services or any data change.
            pending = Path(self.config["writer_directory"]) / "activation.pending"
            new_private_file(pending, b"ACTIVATION_PENDING\n")
            pending.chmod(0o644)
            directory_sync(pending.parent)
            try:
                self.services("stop")
                self.phase(identity, "SERVICES_STOPPED")
                # Recheck under the stopped supervisor's lifetime exclusion.
                with process_lock(self.directory / "authority.lock"), process_lock(Path(self.config["vault_directory"]) / "recovery.lock"):
                    if time.monotonic_ns() >= packet["deadline_ns"]:
                        raise Denied("ACTIVATION_PLAN_EXPIRED")
                    if self.inspect_keys(candidate) != packet["facts"]:
                        raise Denied("ACTIVATION_BASELINE_CHANGED")
                    with _deadline(30), self.writers.exclusive(timeout=30):
                        with self.gate.connect() as db:
                            current = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
                            if current["epoch"] != gate["epoch"] or current["activated"]:
                                raise Denied("ACTIVATION_BASELINE_CHANGED")
                        atomic(self.config["targets"], canonical(packet["policy"]), 0o644)
                        self.phase(identity, "POLICY_WRITTEN")
                        claims = {"v": 1, "type": "hostorbit.recovery-activation", "activation_id": identity,
                            "instance_id": gate["instance_id"], "host_binding": gate["host_binding"], "policy_digest": candidate.digest,
                            "source_instance": self.binding["source_instance"], "source_backup_hash": self.binding["source_backup_hash"],
                            "owner_id": actor["id"], "report_sha256": packet["report_sha256"],
                            "allowed_targets": packet["allowed_targets"], "quarantined_targets": packet["quarantined_targets"],
                            "open_incidents": bool(incidents)}
                        envelope = {"claims": claims, "signature": base64.b64encode(self.key.sign(canonical(claims)).signature).decode()}
                        # Root already owns the exclusive admission lock. A
                        # second shared flock here would deadlock against it.
                        copy_store = Store(self.config["database"], access=self.store.access)
                        with copy_store.write(kind="control") as db:
                            owner = db.execute("SELECT revision,role,disabled FROM users WHERE id=?", (actor["id"],)).fetchone()
                            if owner is None or tuple(owner) != (actor["revision"], "Owner", 0):
                                raise Denied("ACTIVATION_OWNER_CHANGED")
                            for target in candidate.targets.values():
                                db.execute("INSERT INTO resources VALUES(?,?,?,1,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                                    "scope_digest=excluded.scope_digest,policy_revision=excluded.policy_revision,revision=resources.revision+1,enabled=excluded.enabled",
                                    (target.id, target.scope_digest, target.revision, int(target.id in packet["allowed_targets"]), int(time.time()), int(time.time())))
                            self.store.event(db, at=int(time.time()), actor=actor["id"], kind="recovery.activated", target=gate["instance_id"],
                                outcome="ACTIVE_WITH_QUARANTINE", correlation=identity, details=claims)
                        self.phase(identity, "APP_COMMITTED")
                        atomic(self.directory / "activation.json", canonical(envelope))
                        with self.gate.write() as db:
                            db.execute("UPDATE gate SET activated=1,state='NORMAL',epoch=epoch+1,policy_digest=? WHERE id=1", (candidate.digest,))
                        self.phase(identity, "GATE_COMMITTED")
                        self.phase(identity, "AUTHORIZED")
                        self.writers._activate_verified(checksum(envelope))
                        pending.unlink()
                        directory_sync(pending.parent)
                self.services("start")
                self.phase(identity, "ACTIVE")
                return {"status": "ACTIVE", "activation_id": identity, "allowed_targets": packet["allowed_targets"],
                        "quarantined_targets": packet["quarantined_targets"], "manual_isolation": "OWNER_ATTESTED",
                        "restore_verified": False, "backup_gate": "DENIED"}
            except BaseException:
                # No rollback of partial DB/policy commits. Keep the durable
                # block until a separately reviewed recovery, never auto-resume.
                if not pending.exists():
                    new_private_file(pending, b"ACTIVATION_PENDING\n")
                    pending.chmod(0o644)
                    directory_sync(pending.parent)
                self.phase(identity, "RECOVERY_BLOCKED", "ACTIVATION_INTERRUPTED")
                raise
