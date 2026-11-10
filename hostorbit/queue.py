"""Durable observation jobs. Infrastructure mutation is not an enqueue capability."""

from dataclasses import dataclass
import json
import re
import secrets
import time

from .auth import AuthService, etag
from .database import Store, identifier
from .errors import Denied
from .runtime.protocol import SHA256, ULID, canonical, checksum, integer, text


_TERMINAL = {"SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME", "CANCELLED_SAFE"}
_NEXT = {"QUEUED": "INTENT_PREPARED", "INTENT_PREPARED": "DISPATCHING", "DISPATCHING": "EXECUTING", "EXECUTING": "VERIFYING", "VERIFYING": "SUCCEEDED"}


@dataclass(frozen=True)
class Claim:
    job_id: str
    worker_id: str
    nonce: str


class JobQueue:
    def __init__(self, store: Store, *, clock=time.time):
        self.store, self.clock = store, clock

    @staticmethod
    def _schema(db):
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise Denied("QUEUE_SCHEMA_REQUIRES_VERIFIED_MIGRATION", 503)

    def _event(self, db, row, event, *, reason=None):
        self.store.event(db, at=int(self.clock()), actor=row["actor_id"], kind=event,
                         target=row["resource_id"], outcome=row["status"], correlation=row["id"],
                         details={"job_id": row["id"], "revision": row["revision"], "reason": reason})

    def register_resource(self, identity, scope_digest, policy_revision):
        """Local provisioning from an independently installed protected policy summary."""
        text(identity, ULID)
        text(scope_digest, SHA256)
        integer(policy_revision, 1, 2**31 - 1)
        with self.store.write() as db:
            self._schema(db)
            if db.execute("SELECT 1 FROM resources WHERE id=?", (identity,)).fetchone():
                raise Denied("RESOURCE_ALREADY_REGISTERED", 409)
            now = int(self.clock())
            db.execute("INSERT INTO resources VALUES(?,?,?,1,1,?,?)", (identity, scope_digest, policy_revision, now, now))
            self.store.event(db, at=now, actor="local-owner-cli", kind="resource.observation_registered", target=identity,
                             outcome="SUCCEEDED", correlation=identifier(), details={"policy_revision": policy_revision, "scope_digest": scope_digest})

    @staticmethod
    def _actor(db, actor_id, resource, permission="vps:probe"):
        row = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (actor_id,)).fetchone()
        if row is None:
            raise Denied("ACTOR_REVOKED")
        AuthService.require(db, row, permission, resource)

    @staticmethod
    def _public(row):
        return {**{key: row[key] for key in ("id", "resource_id", "action", "status", "revision", "reason", "created_at", "updated_at")},
                "observed_at": json.loads(row["result"])["observed_at"] if row["result"] else None,
                "result": json.loads(row["result"]) if row["result"] else None}

    def enqueue_probe(self, auth, token, csrf, resource, request_key):
        text(resource, ULID, "RESOURCE_NOT_FOUND")
        if not isinstance(request_key, str) or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", request_key) is None:
            raise Denied("IDEMPOTENCY_KEY_REQUIRED", 400)
        payload_hash = checksum({"resource_id": resource, "action": "host.probe"})
        with self.store.write() as db:
            self._schema(db)
            actor = auth._session(db, token, csrf=csrf, mutating=True)
            self._actor(db, actor["id"], resource)
            target = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (resource,)).fetchone()
            if target is None:
                raise Denied("RESOURCE_NOT_FOUND", 404)
            previous = db.execute("SELECT * FROM request_keys WHERE actor_id=? AND namespace='host.probe' AND request_key=?", (actor["id"], request_key)).fetchone()
            now = int(self.clock())
            if previous is not None and previous["expires_at"] > now:
                if previous["payload_hash"] != payload_hash:
                    raise Denied("IDEMPOTENCY_CONFLICT", 409)
                return self._public(db.execute("SELECT * FROM jobs WHERE id=?", (previous["job_id"],)).fetchone())
            if previous is not None:
                db.execute("DELETE FROM request_keys WHERE actor_id=? AND namespace='host.probe' AND request_key=?", (actor["id"], request_key))
            job_id = identifier()
            db.execute("""INSERT INTO jobs(id,actor_id,resource_id,action,payload_hash,scope_digest,policy_revision,status,created_at,updated_at)
                          VALUES(?,?,?,'host.probe',?,?,?,'QUEUED',?,?)""",
                       (job_id, actor["id"], resource, payload_hash, target["scope_digest"], target["policy_revision"], now, now))
            db.execute("INSERT INTO request_keys VALUES(?,'host.probe',?,?,?,?)", (actor["id"], request_key, payload_hash, job_id, now + 86400))
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            self._event(db, row, "job.accepted")
            return self._public(row)

    def _read_job(self, db, auth, token, job_id):
        self._schema(db)
        actor = auth._session(db, token)
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise Denied("RESOURCE_NOT_FOUND", 404)
        try:
            self._actor(db, actor["id"], row["resource_id"], "vps:read")
        except Denied:
            raise Denied("RESOURCE_NOT_FOUND", 404) from None
        return row

    def get(self, auth, token, job_id):
        with self.store.read() as db:
            row = self._read_job(db, auth, token, job_id)
            public = self._public(row)
            return public, etag(public, row["revision"])

    def timeline(self, auth, token, job_id):
        with self.store.read() as db:
            job = self._read_job(db, auth, token, job_id)
            rows = db.execute("""SELECT seq,at,event,outcome,details FROM audit
                WHERE target_id=? AND correlation_id=?
                AND event IN ('job.accepted','job.transition','job.finished')
                ORDER BY seq LIMIT 101""", (job["resource_id"], job_id)).fetchall()
            if len(rows) > 100:
                raise Denied("JOB_TIMELINE_INVALID", 503)
            items = []
            previous = None
            for revision, row in enumerate(rows, 1):
                try:
                    details = json.loads(row["details"])
                    reason = details["reason"]
                    status = row["outcome"]
                    if (not isinstance(details, dict) or details.get("job_id") != job_id
                            or type(details.get("revision")) is not int or details["revision"] != revision
                            or type(row["at"]) is not int or not 0 <= row["at"] <= 253402300799
                            or (row["event"] == "job.accepted" and (previous is not None or status != "QUEUED"))
                            or (row["event"] == "job.transition" and
                                (previous not in _NEXT or _NEXT[previous] != status or status == "SUCCEEDED"))
                            or (row["event"] == "job.finished" and
                                (previous is None or previous in _TERMINAL or status not in _TERMINAL
                                 or (status == "SUCCEEDED" and previous != "VERIFYING")
                                 or (status == "CANCELLED_SAFE" and previous not in ("QUEUED", "INTENT_PREPARED"))))
                            or (row["event"] != "job.finished" and reason is not None)
                            or (row["event"] == "job.finished" and (not isinstance(reason, str)
                                or re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", reason) is None))):
                        raise ValueError
                except (ValueError, TypeError, KeyError):
                    raise Denied("JOB_TIMELINE_INVALID", 503) from None
                items.append({"seq": row["seq"], "at": row["at"], "status": status, "reason": reason})
                previous = status
            # Old recovery imports changed the Job atomically with this global event,
            # but did not append a per-Job finish event or increment its revision.
            if (items and len(items) == job["revision"] and previous not in _TERMINAL
                    and job["reason"] == "RESTORE_QUARANTINE"
                    and job["status"] == ("CANCELLED_SAFE" if previous == "QUEUED" else "UNKNOWN_OUTCOME")):
                imported = db.execute("SELECT seq,at FROM audit WHERE event='recovery.imported' AND outcome='READ_ONLY_RECOVERY' AND seq>? ORDER BY seq LIMIT 1",
                                      (items[-1]["seq"],)).fetchone()
                if imported is None or type(imported["at"]) is not int or not 0 <= imported["at"] <= 253402300799:
                    raise Denied("JOB_TIMELINE_INVALID", 503)
                items.append({"seq": imported["seq"], "at": imported["at"], "status": job["status"],
                              "reason": job["reason"], "source": "recovery.imported"})
                return {"items": items}
            if not items or len(items) != job["revision"] or previous != job["status"] or items[-1]["reason"] != job["reason"]:
                raise Denied("JOB_TIMELINE_INVALID", 503)
            return {"items": items}

    def recover(self, classify=None):
        """The caller must hold the exclusive Worker process lock, never an expiring lease."""
        with self.store.read() as db:
            self._schema(db)
            rows = db.execute("SELECT * FROM jobs WHERE claimed_by IS NOT NULL AND status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')").fetchall()
        for row in rows:
            outcome = classify(row) if classify is not None else "UNKNOWN_OUTCOME"
            with self.store.write(kind="control") as db:
                current = db.execute("SELECT * FROM jobs WHERE id=? AND claim_nonce=? AND status=?", (row["id"], row["claim_nonce"], row["status"])).fetchone()
                if current is not None:
                    self._finish(db, current, outcome, "WORKER_RESTART")

    def claim(self, worker_id):
        text(worker_id, ULID)
        with self.store.write(kind="dispatch") as db:
            self._schema(db)
            for row in db.execute("SELECT * FROM jobs WHERE status='QUEUED' AND claimed_by IS NULL ORDER BY created_at,id LIMIT 100").fetchall():
                try:
                    self._actor(db, row["actor_id"], row["resource_id"])
                except Denied:
                    self._finish(db, row, "CANCELLED_SAFE", "ACTOR_REVOKED")
                    continue
                target = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (row["resource_id"],)).fetchone()
                if target is None or target["scope_digest"] != row["scope_digest"] or target["policy_revision"] != row["policy_revision"]:
                    self._finish(db, row, "CANCELLED_SAFE", "STALE_SCOPE")
                    continue
                nonce = secrets.token_hex(32)
                db.execute("UPDATE jobs SET claimed_by=?,claim_nonce=? WHERE id=?", (worker_id, nonce, row["id"]))
                return Claim(row["id"], worker_id, nonce), dict(row)
        return None

    def binding(self, row):
        # Observations have no approved mutating Change Plan. These IDs bind the immutable read request.
        return {"job_id": row["id"], "plan_id": row["id"], "revision": 1, "plan_digest": row["payload_hash"],
                "approval_id": row["id"], "actor_id": row["actor_id"], "target": row["resource_id"],
                "capability": row["action"], "scope_digest": row["scope_digest"]}

    @staticmethod
    def _claimed(db, claim):
        row = db.execute("SELECT * FROM jobs WHERE id=? AND claimed_by=? AND claim_nonce=?", (claim.job_id, claim.worker_id, claim.nonce)).fetchone()
        if row is None or row["status"] in _TERMINAL:
            raise Denied("JOB_CLAIM_INVALID")
        return row

    def advance(self, claim, state, *, permit=None):
        with self.store.write(kind="control") as db:
            row = self._claimed(db, claim)
            if _NEXT.get(row["status"]) != state or state == "SUCCEEDED":
                raise Denied("JOB_TRANSITION_DENIED")
            self._actor(db, row["actor_id"], row["resource_id"])
            target = db.execute("SELECT scope_digest,policy_revision,enabled FROM resources WHERE id=?", (row["resource_id"],)).fetchone()
            if not target["enabled"] or target["scope_digest"] != row["scope_digest"] or target["policy_revision"] != row["policy_revision"]:
                raise Denied("STALE_SCOPE")
            if state == "INTENT_PREPARED":
                if permit is None or permit.get("claims") is None or any(permit["claims"].get(k) != v for k, v in self.binding(row).items()):
                    raise Denied("PERMIT_BINDING_INVALID")
            db.execute("UPDATE jobs SET status=?,revision=revision+1,permit=coalesce(?,permit),updated_at=? WHERE id=?",
                       (state, canonical(permit).decode() if permit else None, int(self.clock()), row["id"]))
            self._event(db, db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone(), "job.transition")

    def _finish(self, db, row, outcome, reason, result=None):
        if row["status"] in _TERMINAL or outcome not in _TERMINAL:
            raise Denied("JOB_TRANSITION_DENIED")
        text(reason, r"[A-Z][A-Z0-9_]{1,63}")
        if outcome == "SUCCEEDED" and row["status"] != "VERIFYING":
            raise Denied("JOB_TRANSITION_DENIED")
        if outcome == "CANCELLED_SAFE" and row["status"] not in ("QUEUED", "INTENT_PREPARED"):
            raise Denied("JOB_TRANSITION_DENIED")
        db.execute("UPDATE jobs SET status=?,revision=revision+1,result=?,reason=?,updated_at=? WHERE id=?",
                   (outcome, canonical(result).decode() if result else None, reason, int(self.clock()), row["id"]))
        if outcome == "UNKNOWN_OUTCOME":
            db.execute("INSERT INTO job_incidents VALUES(?,?,'OPEN',?)", (identifier(), row["id"], int(self.clock())))
        if reason == "SSH_HOST_KEY_MISMATCH":
            self.store.event(db, at=int(self.clock()), actor=row["actor_id"], kind="security.ssh_host_key_mismatch",
                             target=row["resource_id"], outcome="DENIED", correlation=row["id"], details={"job_id": row["id"]})
        self._event(db, db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone(), "job.finished", reason=reason)

    def finish(self, claim, outcome, reason, *, result=None):
        with self.store.write(kind="control") as db:
            self._finish(db, self._claimed(db, claim), outcome, reason, result)
