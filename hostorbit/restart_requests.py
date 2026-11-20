"""Durable, revision-bound requests for the isolated Docker restart flow."""

import json

from .auth import Role
from .change_drafts import _baseline, _checked_draft, _latest, _probe_key, _require, _session, _stored, check_draft_approval
from .database import Store
from .errors import Denied

REQUESTED = "change_plan.restart_requested"
AC28_EVENTS = (REQUESTED, "change_plan.restart_prepared", "change_plan.restart_finished")
RECONCILIATION_EVENTS = ("change_plan.restart_reconciliation_requested", "change_plan.restart_reconciled")
RESOLVED = ("RECONCILED_SUCCEEDED", "RECONCILED_FAILED")
MAX_AGE = 300


def request_restart(db, source, queue, auth, token, csrf, draft_id, *, if_match, probe_id, request_key, approval_id):
    row, draft, actor = _checked_draft(db, auth, token, draft_id, if_match, csrf=csrf, mutating=True)
    if actor["role"] != Role.OWNER:
        raise Denied("CHANGE_PLAN_APPROVAL_OWNER_REQUIRED", 403)
    request_binding = _probe_key(row["plan_hash"], draft["baseline"], request_key)
    previous = db.execute("""SELECT details FROM audit WHERE target_id=? AND correlation_id=? AND event=?
                            AND json_extract(details,'$.approval_id')=? ORDER BY seq DESC LIMIT 1""",
                          (row["resource_id"], draft_id, REQUESTED, approval_id)).fetchone()
    if previous:
        details = json.loads(previous["details"])
        if details["actor_id"] != actor["id"] or details["observation_id"] != probe_id or details["revision"] != row["revision"] or details["request_binding"] != request_binding:
            raise Denied("RESTART_REQUEST_CONFLICT", 409)
        latest = db.execute("""SELECT outcome FROM audit WHERE target_id=? AND correlation_id=?
            AND event IN (?,?,?) AND json_extract(details,'$.operation_id')=? ORDER BY seq DESC LIMIT 1""",
                            (row["resource_id"], draft_id, *AC28_EVENTS, details["operation_id"])).fetchone()
        return {"id": details["operation_id"], "revision": row["revision"], "status": latest["outcome"]}

    result = check_draft_approval(db, source, auth, token, draft_id, if_match=if_match, probe_id=probe_id,
                                  request_key=request_key, approval_id=approval_id)
    started_at = result.get("started_at")
    if started_at is None or draft["baseline"].get("started_at") != started_at:
        raise Denied("RESTART_V8_BASELINE_REQUIRED", 409)
    approval = db.execute("SELECT at,id FROM audit WHERE seq=?", (result["audit_seq"],)).fetchone()
    now = int(auth.clock())
    if not 0 <= now - approval["at"] <= MAX_AGE:
        raise Denied("CHANGE_PLAN_APPROVAL_EXPIRED", 409)
    baseline = draft["baseline"]
    operation = {"operation_id": approval["id"], "actor_id": actor["id"], "revision": row["revision"],
                 "plan_hash": row["plan_hash"], "request_binding": request_binding, "approval_id": approval_id, "approval_seq": result["audit_seq"],
                 "observation_id": probe_id, "container_id": baseline["target"]["id"],
                 "boot_id": baseline["boot_id"], "started_at": started_at, "scope_digest": baseline["scope_digest"]}
    Store.event(db, at=now, actor=actor["id"], target=row["resource_id"], correlation=draft_id,
                kind=REQUESTED, outcome="QUEUED", details=operation)
    queue.enqueue_restart(db, operation["operation_id"], actor["id"], row["resource_id"], baseline["scope_digest"],
                          baseline["policy_revision"], row["plan_hash"])
    return {"id": operation["operation_id"], "revision": row["revision"], "status": "QUEUED"}


def validate_request(db, event, now):
    """Recheck authoritative DB state in the dispatch transaction."""
    operation = json.loads(event["details"])
    if db.execute("""SELECT 1 FROM audit u WHERE u.event=? AND u.outcome='UNKNOWN_OUTCOME'
        AND NOT EXISTS (SELECT 1 FROM audit r WHERE r.event=? AND r.outcome IN (?,?)
            AND r.target_id=u.target_id AND r.correlation_id=u.correlation_id
            AND json_extract(r.details,'$.operation_id')=json_extract(u.details,'$.operation_id')) LIMIT 1""",
                  (AC28_EVENTS[2], RECONCILIATION_EVENTS[1], *RESOLVED)).fetchone():
        raise Denied("RESTART_INCIDENT_OPEN", 409)
    row = _latest(db, event["correlation_id"])
    draft = _stored(row)
    if (row["revision"] != operation["revision"] or row["plan_hash"] != operation["plan_hash"]
            or row["resource_id"] != event["target_id"] or event["actor_id"] != operation["actor_id"]):
        raise Denied("STALE_REVISION", 409)
    actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (event["actor_id"],)).fetchone()
    if actor is None or actor["role"] != Role.OWNER:
        raise Denied("CHANGE_PLAN_APPROVAL_OWNER_REQUIRED", 403)
    _require(db, actor, row["resource_id"], restart=True)

    approval = db.execute("SELECT * FROM audit WHERE seq=?", (operation["approval_seq"],)).fetchone()
    if (approval is None or approval["id"] != operation["operation_id"] or approval["actor_id"] != actor["id"]
            or approval["target_id"] != row["resource_id"] or approval["correlation_id"] != row["id"]
            or approval["event"] != "change_plan.approval_recorded" or approval["outcome"] != "SUCCEEDED"
            or not 0 <= now - approval["at"] <= MAX_AGE):
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    details = json.loads(approval["details"])
    if (details.get("backup_gate") != "BACKUP_NOT_REQUIRED"
            or any(details.get(key) != operation[key] for key in
                   ("approval_id", "plan_hash", "revision", "observation_id", "started_at"))):
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    baseline = draft["baseline"]
    current = _baseline(db, row["resource_id"], baseline["target"]["id"], now)
    if (current["target"] != baseline["target"]
            or any(current[key] != baseline[key] for key in ("resource_revision", "policy_revision"))
            or any(current.get(key) != operation[key] for key in ("observation_id", "boot_id", "started_at", "scope_digest"))
            or current["target"]["id"] != operation["container_id"]
            or (current.get("mount_status"), current.get("network_status"), current.get("dependency_status"))
               != ("NONE", "ISOLATED", "ISOLATED")):
        raise Denied("STALE_BASELINE", 409)
    return operation


def request_reconciliation(db, auth, token, csrf, draft_id, operation_id, attempt):
    actor = _session(db, auth, token, csrf=csrf, mutating=True)
    target = _latest(db, draft_id)["resource_id"]
    _require(db, actor, target, restart=True)
    if actor["role"] != Role.OWNER:
        raise Denied("CHANGE_PLAN_APPROVAL_OWNER_REQUIRED", 403)
    binding = (target, draft_id, operation_id)
    incident = db.execute("""SELECT details FROM audit WHERE target_id=? AND correlation_id=?
        AND json_extract(details,'$.operation_id')=? AND event=? AND outcome='UNKNOWN_OUTCOME'""",
                          (*binding, AC28_EVENTS[2])).fetchone()
    if incident is None:
        raise Denied("RESTART_INCIDENT_NOT_FOUND", 404)
    rows = db.execute("""SELECT outcome, json_extract(details,'$.attempt') AS attempt FROM audit
        WHERE target_id=? AND correlation_id=? AND json_extract(details,'$.operation_id')=?
        AND event IN (?,?) ORDER BY seq DESC""", (*binding, *RECONCILIATION_EVENTS)).fetchall()
    previous = next((row for row in rows if row["attempt"] == attempt), None)
    if previous is not None:
        return {"attempt": attempt, "status": previous["outcome"]}
    if not 1 <= attempt <= 3 or attempt != (rows[0]["attempt"] + 1 if rows else 1) or (rows and rows[0]["outcome"] != "QUARANTINED"):
        raise Denied("RESTART_RECONCILIATION_UNAVAILABLE", 409)
    Store.event(db, at=int(auth.clock()), actor=actor["id"], target=target, correlation=draft_id,
                kind=RECONCILIATION_EVENTS[0], outcome="RECONCILIATION_REQUESTED",
                details={"operation_id": operation_id, "revision": json.loads(incident["details"])["revision"], "attempt": attempt})
    return {"attempt": attempt, "status": "RECONCILIATION_REQUESTED"}


def restart_timeline(db, auth, token, draft_id):
    actor = auth._session(db, token)
    row = _latest(db, draft_id)
    _require(db, actor, row["resource_id"], restart=False)
    events = db.execute("""SELECT seq,at,event,outcome,details FROM audit WHERE target_id=? AND correlation_id=?
                          AND event IN (?,?,?,?,?) ORDER BY seq DESC LIMIT 100""",
                        (row["resource_id"], draft_id, *AC28_EVENTS, *RECONCILIATION_EVENTS)).fetchall()
    return {"items": [{"seq": event["seq"], "at": event["at"], "event": event["event"],
                       "status": event["outcome"], "operation_id": (details := json.loads(event["details"]))["operation_id"],
                       "revision": details["revision"], "reason": details.get("reason"), "attempt": details.get("attempt")}
                      for event in reversed(events)]}


class RestartOperations:
    def __init__(self, queue, gate, broker, secret_refs):
        self.queue, self.store, self.clock = queue, queue.store, queue.clock
        self.gate, self.broker, self.secret_refs = gate, broker, secret_refs

    def recover_legacy_requests(self):
        # Requests from schema 3 lived only in audit. Never send them from the new queue.
        with self.store.write(kind="control") as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 4:
                return
            for row in db.execute("""SELECT a.* FROM audit a WHERE a.event=?
                AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id=json_extract(a.details,'$.operation_id'))
                AND NOT EXISTS (SELECT 1 FROM audit b WHERE b.event=? AND b.target_id=a.target_id
                    AND b.correlation_id=a.correlation_id
                    AND json_extract(b.details,'$.operation_id')=json_extract(a.details,'$.operation_id'))
                ORDER BY a.seq""", (REQUESTED, AC28_EVENTS[2])).fetchall():
                operation = json.loads(row["details"])
                prepared = db.execute("""SELECT 1 FROM audit WHERE event=? AND target_id=? AND correlation_id=?
                    AND json_extract(details,'$.operation_id')=? LIMIT 1""",
                    (AC28_EVENTS[1], row["target_id"], row["correlation_id"], operation["operation_id"])).fetchone()
                Store.event(db, at=int(self.clock()), actor=row["actor_id"], target=row["target_id"],
                            correlation=row["correlation_id"], kind=AC28_EVENTS[2],
                            outcome="UNKNOWN_OUTCOME" if prepared else "CANCELLED_SAFE",
                            details={"operation_id": operation["operation_id"], "revision": operation["revision"],
                                     "reason": "WORKER_RESTART"})

    @staticmethod
    def pending_reconciliation(db):
        return db.execute("""SELECT a.* FROM audit a WHERE a.event=? AND NOT EXISTS
            (SELECT 1 FROM audit r WHERE r.event=? AND r.correlation_id=a.correlation_id
             AND json_extract(r.details,'$.request_seq')=a.seq) ORDER BY a.seq LIMIT 1""", RECONCILIATION_EVENTS).fetchone()

    def reconcile_one(self, row):
        from .runtime.protocol import SHA256, checksum, fields, text

        details = json.loads(row["details"])
        job_id = details["operation_id"]
        outcome, digest = "QUARANTINED", None
        try:
            # These RPCs only read the durable local journals. Neither can send SSH or issue a permit.
            saved = self.broker.call("receipt.get", {"job_id": job_id})
            fields(saved, ("outcome", "code", "observation", "authority_receipt"))
            receipt = self.gate.call("attempt.status", {"job_id": job_id})
            fields(receipt, ("job_id", "nonce", "state", "result_digest", "result_code"))
            result = {key: saved[key] for key in ("outcome", "code", "observation")}
            text(receipt["nonce"], SHA256)
            if (receipt != saved["authority_receipt"] or receipt["job_id"] != job_id
                    or receipt["state"] != saved["outcome"] or receipt["result_code"] != saved["code"]
                    or receipt["result_digest"] != checksum(result) or saved["observation"] is not None):
                raise Denied("BROKER_RECEIPT_INVALID")
            digest = receipt["result_digest"]
            reason = text(saved["code"], r"[A-Z][A-Z0-9_]{1,63}")
            if receipt["state"] == "SUCCEEDED" and reason in ("DOCKER_RESTART_VERIFIED", "RESTART_ALREADY_VERIFIED"):
                outcome = "RECONCILED_SUCCEEDED"
            elif receipt["state"] == "FAILED" and reason in ("STALE_BASELINE", "CONTAINER_NOT_APPROVED", "CONTAINER_NOT_ISOLATED"):
                outcome = "RECONCILED_FAILED"
        except Denied as error:
            reason = error.code
        with self.store.write(kind="control") as db:
            try:
                actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (row["actor_id"],)).fetchone()
                if actor is None or actor["role"] != Role.OWNER:
                    raise Denied("CHANGE_PLAN_APPROVAL_OWNER_REQUIRED")
                _require(db, actor, row["target_id"], restart=True)
            except Denied as error:
                outcome, reason = "QUARANTINED", error.code
            if outcome in RESOLVED:
                db.execute("DELETE FROM job_incidents WHERE job_id=?", (job_id,))
            Store.event(db, at=int(self.clock()), actor=row["actor_id"], target=row["target_id"], correlation=row["correlation_id"],
                        kind=RECONCILIATION_EVENTS[1], outcome=outcome,
                        details={**details, "request_seq": row["seq"], "reason": reason, "receipt_digest": digest})
        return True

    def reconcile_pending(self):
        with self.store.write(kind="dispatch") as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in (3, 4):
                return False
            row = self.pending_reconciliation(db)
        return self.reconcile_one(row) if row is not None else False

    def prepare(self, job):
        from .runtime.protocol import restart_payload

        with self.store.read() as db:
            row = self.queue.restart_request(db, job["id"])
            if row is None:
                raise Denied("RESTART_REQUEST_NOT_FOUND")
            operation = validate_request(db, row, int(self.clock()))
        secret_ref = self.secret_refs.get(job["resource_id"])
        if secret_ref is None:
            raise Denied("CAPABILITY_DISABLED")
        if (job["resource_id"] != row["target_id"] or job["actor_id"] != row["actor_id"]
                or job["payload_hash"] != operation["plan_hash"] or job["scope_digest"] != operation["scope_digest"]):
            raise Denied("STALE_SCOPE")
        payload = restart_payload({key: operation[key] for key in
                                   ("operation_id", "container_id", "boot_id", "started_at")})

        def revalidate(db):
            if validate_request(db, row, int(self.clock())) != operation:
                raise Denied("STALE_BASELINE")

        anchor = self.gate.call("time.anchor", {"plan_id": row["correlation_id"], "revision": operation["revision"]})
        binding = {"job_id": job["id"], "plan_id": row["correlation_id"], "revision": operation["revision"],
                   "plan_digest": job["payload_hash"], "approval_id": operation["approval_id"], "actor_id": job["actor_id"],
                   "target": job["resource_id"], "capability": job["action"], "scope_digest": job["scope_digest"],
                   "time_anchor": anchor, "restart": payload}
        return binding, secret_ref, revalidate
