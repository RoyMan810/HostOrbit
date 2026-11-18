"""Scoped read model for one saved Docker restart revision and its audit evidence."""

import json

from .change_drafts import _public, _require, _session, _stored
from .errors import Denied
from .restart_requests import AC28_EVENTS, REQUESTED


def audit_plan_revision(db, auth, token, draft_id, revision):
    actor = _session(db, auth, token)
    auth.require(db, actor, "audit:read", "*")
    row = db.execute("SELECT * FROM change_plan_drafts WHERE id=? AND revision=?", (draft_id, revision)).fetchone()
    if row is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    _require(db, actor, row["resource_id"], restart=False)
    plan, _ = _public(_stored(row), row["plan_hash"])
    binding = (row["resource_id"], draft_id, revision, row["plan_hash"])
    # Later worker events carry only the operation ID and revision. Bind them
    # through the accepted request, which pins the plan hash and container.
    request = db.execute("""SELECT seq,details FROM audit WHERE target_id=? AND correlation_id=?
        AND json_extract(details,'$.revision')=? AND json_extract(details,'$.plan_hash')=?
        AND event=? AND outcome='QUEUED' AND json_extract(details,'$.container_id')=?
        ORDER BY seq DESC LIMIT 1""", (*binding, REQUESTED, plan["baseline"]["target"]["id"])).fetchone()
    operation = None
    decision_seq = None
    if request:
        accepted = json.loads(request["details"])
        approval = db.execute("""SELECT json_extract(details,'$.backup_audit_seq') FROM audit
            WHERE target_id=? AND correlation_id=? AND json_extract(details,'$.revision')=?
            AND json_extract(details,'$.plan_hash')=? AND event='change_plan.approval_recorded'
            AND outcome='SUCCEEDED' AND seq=? AND id=? AND json_extract(details,'$.approval_id')=?""",
            (*binding, accepted["approval_seq"], accepted["operation_id"], accepted["approval_id"])).fetchone()
        if approval is None or type(approval[0]) is not int:
            raise Denied("CHANGE_PLAN_INTEGRITY", 503)
        decision_seq = approval[0]
        latest = db.execute("""SELECT outcome,json_extract(details,'$.reason') AS reason FROM audit
            WHERE target_id=? AND correlation_id=? AND json_extract(details,'$.revision')=?
            AND json_extract(details,'$.operation_id')=? AND event IN (?,?,?) AND seq>=?
            ORDER BY seq DESC LIMIT 1""",
            (*binding[:3], accepted["operation_id"], *AC28_EVENTS, request["seq"])).fetchone()
        operation = {"id": accepted["operation_id"], "status": latest["outcome"], "reason": latest["reason"]}

    backup = db.execute("""SELECT details FROM audit WHERE target_id=? AND correlation_id=?
        AND json_extract(details,'$.revision')=? AND json_extract(details,'$.plan_hash')=?
        AND event='change_plan.backup_evaluated' AND (? IS NULL OR seq=?)
        ORDER BY seq DESC LIMIT 1""", (*binding, decision_seq, decision_seq)).fetchone()
    if decision_seq is not None and backup is None:
        raise Denied("CHANGE_PLAN_INTEGRITY", 503)
    decision = None
    if backup:
        details = json.loads(backup["details"])
        decision = {"gate": details["backup_gate"], "reason": details["backup_gate_reason"]}
    return {"plan": plan, "backup_decision": decision, "operation": operation}
