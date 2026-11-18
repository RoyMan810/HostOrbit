"""Durable, revision-bound requests for the isolated Docker restart flow."""

import json

from .auth import Role
from .change_drafts import _baseline, _checked_draft, _latest, _probe_key, _require, _stored, check_draft_approval
from .database import Store
from .errors import Denied

REQUESTED = "change_plan.restart_requested"
AC28_EVENTS = (REQUESTED, "change_plan.restart_prepared", "change_plan.restart_finished")
MAX_AGE = 300


def request_restart(db, source, auth, token, csrf, draft_id, *, if_match, probe_id, request_key, approval_id):
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
    return {"id": operation["operation_id"], "revision": row["revision"], "status": "QUEUED"}


def validate_request(db, event, now):
    """Recheck authoritative DB state in the dispatch transaction."""
    operation = json.loads(event["details"])
    if db.execute("""SELECT 1 FROM audit WHERE target_id=? AND event=? AND outcome='UNKNOWN_OUTCOME' LIMIT 1""",
                  (event["target_id"], AC28_EVENTS[2])).fetchone():
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


def restart_timeline(db, auth, token, draft_id):
    actor = auth._session(db, token)
    row = _latest(db, draft_id)
    _require(db, actor, row["resource_id"], restart=False)
    events = db.execute("""SELECT seq,at,event,outcome,details FROM audit WHERE target_id=? AND correlation_id=?
                          AND event IN (?,?,?) ORDER BY seq DESC LIMIT 100""",
                        (row["resource_id"], draft_id, *AC28_EVENTS)).fetchall()
    return {"items": [{"seq": event["seq"], "at": event["at"], "event": event["event"],
                       "status": event["outcome"], "operation_id": (details := json.loads(event["details"]))["operation_id"],
                       "revision": details["revision"], "reason": details.get("reason")}
                      for event in reversed(events)]}


class RestartWorker:
    def __init__(self, store, gate, broker, clock, secret_refs):
        self.store, self.gate, self.broker, self.clock, self.secret_refs = store, gate, broker, clock, secret_refs

    @staticmethod
    def waiting(db, from_event, until_events):
        return db.execute("""SELECT a.* FROM audit a WHERE a.event=? AND NOT EXISTS (
            SELECT 1 FROM audit b WHERE b.seq>a.seq AND b.correlation_id=a.correlation_id
            AND b.target_id=a.target_id AND b.event IN (?,?) AND
            json_extract(b.details,'$.operation_id')=json_extract(a.details,'$.operation_id'))
            ORDER BY a.seq LIMIT 1""", (from_event, *until_events)).fetchone()

    def event(self, db, row, operation, kind, outcome, reason=None):
        Store.event(db, at=int(self.clock()), actor=row["actor_id"], target=row["target_id"],
                    correlation=row["correlation_id"], kind=kind, outcome=outcome,
                    details={"operation_id": operation["operation_id"], "revision": operation["revision"], "reason": reason})

    def recover(self):
        # Worker already holds its lifetime process lock. An interrupted dispatch
        # never re-enters the Broker, even when its final receipt was lost.
        with self.store.write(kind="control") as db:
            row = self.waiting(db, AC28_EVENTS[1], (AC28_EVENTS[2], AC28_EVENTS[2]))
            if row is not None:
                self.event(db, row, json.loads(row["details"]), AC28_EVENTS[2], "UNKNOWN_OUTCOME", "WORKER_RESTART")

    def run_one(self):
        from .runtime.protocol import checksum, fields, restart_payload, text

        try:
            with self.store.write(kind="dispatch") as db:
                if db.execute("PRAGMA user_version").fetchone()[0] != 3:
                    return False
                row = self.waiting(db, REQUESTED, AC28_EVENTS[1:])
                if row is None:
                    return False
                operation = json.loads(row["details"])
                try:
                    operation = validate_request(db, row, int(self.clock()))
                    secret_ref = self.secret_refs.get(row["target_id"])
                    if secret_ref is None:
                        raise Denied("CAPABILITY_DISABLED")
                    payload = restart_payload({key: operation[key] for key in
                                               ("operation_id", "container_id", "boot_id", "started_at")})
                except Denied as error:
                    self.event(db, row, operation, AC28_EVENTS[2], "CANCELLED_SAFE", error.code)
                    return True
                self.event(db, row, operation, AC28_EVENTS[1], "INTENT_PREPARED")
        except Denied as error:
            if error.code in ("WRITER_ADMISSION_CLOSED", "WRITER_BARRIER_TIMEOUT"):
                return False
            raise

        permit = None
        sent = False
        try:
            anchor = self.gate.call("time.anchor", {"plan_id": row["correlation_id"], "revision": operation["revision"]})
            binding = {"job_id": operation["operation_id"], "plan_id": row["correlation_id"],
                       "revision": operation["revision"], "plan_digest": operation["plan_hash"],
                       "approval_id": operation["approval_id"], "actor_id": row["actor_id"],
                       "target": row["target_id"], "capability": "docker.restart", "scope_digest": operation["scope_digest"],
                       "time_anchor": anchor, "restart": payload}
            permit = self.gate.call("permit.admit", binding)
            with self.store.write(kind="control") as db:
                if validate_request(db, row, int(self.clock())) != operation:
                    raise Denied("STALE_BASELINE")
                # Protect the handoff from a newly archived or revoked plan. The
                # Broker independently consumes the time-bound permit once.
                self.event(db, row, operation, AC28_EVENTS[1], "DISPATCHING")
            sent = True
            response = self.broker.call("use_for_scoped_ssh", {"permit": permit, "secret_ref": secret_ref})
            fields(response, ("outcome", "code", "observation", "authority_receipt"))
            receipt = self.gate.call("attempt.status", {"job_id": operation["operation_id"]})
            result = {key: response[key] for key in ("outcome", "code", "observation")}
            outcome, reason = result["outcome"], text(result["code"], r"[A-Z][A-Z0-9_]{1,63}")
            if (receipt != response["authority_receipt"] or receipt["state"] != outcome
                    or receipt["result_digest"] != checksum(result) or result["observation"] is not None
                    or outcome not in ("SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME")):
                raise Denied("BROKER_RECEIPT_INVALID")
        except Denied as error:
            if permit is not None and not sent:
                try:
                    self.gate.call("permit.cancel", {"job_id": operation["operation_id"], "nonce": permit["claims"]["nonce"]})
                except Denied:
                    pass
            outcome, reason = ("UNKNOWN_OUTCOME" if sent else "CANCELLED_SAFE"), error.code
        with self.store.write(kind="control") as db:
            self.event(db, row, operation, AC28_EVENTS[2], outcome, reason)
        return True
