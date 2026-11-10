"""Versioned Docker restart drafts for a rehearsed schema 3 transaction."""

import json
import re

from .auth import AuthService, check_etag, etag
from .database import Store, identifier
from .errors import Denied
from .inventory import _sample
from .runtime.protocol import SHA256, ULID, canonical, checksum


def _session(db, auth, token, *, csrf=None, mutating=False):
    if not db.in_transaction or db.execute("PRAGMA user_version").fetchone()[0] != 3:
        raise Denied("CHANGE_PLAN_SCHEMA_REQUIRES_VERIFIED_MIGRATION", 503)
    return auth._session(db, token, csrf=csrf, mutating=mutating)


def _require(db, actor, resource_id, *, restart):
    try:
        AuthService.require(db, actor, "vps:read", resource_id)
    except Denied:
        raise Denied("RESOURCE_NOT_FOUND", 404) from None
    if restart:
        AuthService.require(db, actor, "vps:restart", resource_id)


def _latest(db, draft_id):
    if re.fullmatch(ULID, draft_id) is not None:
        row = db.execute("""SELECT * FROM change_plan_drafts WHERE id=?
                            ORDER BY revision DESC LIMIT 1""", (draft_id,)).fetchone()
        if row is not None:
            return row
    raise Denied("RESOURCE_NOT_FOUND", 404)


def _value(draft_id, revision, baseline):
    return {"version": 1, "id": draft_id, "revision": revision, "action": "docker.restart", "state": "DRAFT",
            "baseline": baseline, "diff": {"operation": "RESTART", "configuration": "UNCHANGED"},
            "risk": "TEMPORARY_SERVICE_INTERRUPTION", "preflight": "LOCAL_OBSERVATION_ONLY",
            "backup_gate": "NOT_EVALUATED", "execution": "BLOCKED"}


def _public(value, plan_hash):
    baseline = {key: item for key, item in value["baseline"].items() if key != "scope_digest"}
    public = {**value, "baseline": baseline, "plan_hash": plan_hash}
    return public, etag(public, public["revision"])


def _stored(row):
    baseline = json.loads(row["baseline"])
    value = _value(row["id"], row["revision"], baseline)
    if (checksum(value) != row["plan_hash"] or value["action"] != row["action"]
            or baseline["target"]["resource_id"] != row["resource_id"]):
        raise Denied("CHANGE_PLAN_INTEGRITY", 503)
    return value


def get_draft(db, auth, token, draft_id):
    """Read the latest immutable revision within the caller's transaction."""
    actor = _session(db, auth, token)
    row = _latest(db, draft_id)
    _require(db, actor, row["resource_id"], restart=False)
    return _public(_stored(row), row["plan_hash"])


def _baseline(db, resource_id, container_id, now):
    resource = db.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
    if resource is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    # Match Inventory's latest completed observation, including quarantine from
    # old imports where only job.accepted is available. Pin the exact job ID.
    job = db.execute("""SELECT j.* FROM audit a JOIN jobs j ON j.id=a.correlation_id
                        WHERE a.target_id=? AND j.resource_id=a.target_id AND j.action='host.probe'
                        AND j.status IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')
                        AND (a.event='job.finished' OR (a.event='job.accepted' AND j.reason='RESTORE_QUARANTINE'))
                        ORDER BY a.seq DESC LIMIT 1""", (resource_id,)).fetchone()
    sample = _sample(job["result"]) if job is not None and job["status"] == "SUCCEEDED" else None
    if (not resource["enabled"] or sample is None or job["scope_digest"] != resource["scope_digest"]
            or job["policy_revision"] != resource["policy_revision"] or job["updated_at"] > now
            or not 0 <= now - sample["observed_at"] <= 300):
        raise Denied("FRESH_OBSERVATION_REQUIRED", 409)
    docker = sample.get("docker")
    if docker is None or docker["status"] != "OBSERVED":
        raise Denied("DOCKER_OBSERVATION_REQUIRED", 409)
    container = next((item for item in docker["containers"] if item["id"] == container_id), None)
    if container is None:
        raise Denied("CONTAINER_NOT_FOUND", 404)
    if container["state"] != "RUNNING":
        raise Denied("CONTAINER_NOT_RUNNING", 409)
    return {"target": {"resource_id": resource_id, **container}, "observation_id": job["id"],
            "observed_at": sample["observed_at"], "boot_id": sample["boot_id"],
            "scope_digest": resource["scope_digest"], "resource_revision": resource["revision"],
            "policy_revision": resource["policy_revision"]}


def _checked_draft(db, auth, token, draft_id, if_match):
    actor = _session(db, auth, token)
    row = _latest(db, draft_id)
    _require(db, actor, row["resource_id"], restart=True)
    draft = _stored(row)
    check_etag(if_match, _public(draft, row["plan_hash"])[1])
    return row, draft


def check_draft_baseline(db, auth, token, draft_id, *, if_match):
    """Recheck the exact draft against the local read snapshot."""
    row, draft = _checked_draft(db, auth, token, draft_id, if_match)
    checked_at = int(auth.clock())
    baseline = draft["baseline"]
    current = _baseline(db, row["resource_id"], baseline["target"]["id"], checked_at)
    if current != baseline:
        raise Denied("STALE_BASELINE", 409)
    return {"draft_id": row["id"], "revision": row["revision"], "plan_hash": row["plan_hash"],
            "observation_id": baseline["observation_id"], "checked_at": checked_at,
            "baseline_check": "MATCHED", "backup_gate": draft["backup_gate"], "execution": draft["execution"]}


def _probe_audit(db, resource_id, probe_id):
    return db.execute("""SELECT seq,digest FROM audit WHERE target_id=? AND correlation_id=?
                         AND event='job.finished' AND outcome='SUCCEEDED' ORDER BY seq DESC LIMIT 1""",
                      (resource_id, probe_id)).fetchone()


def _probe_source(draft_db, source_db, auth, token, resource_id, original_probe_id):
    if (not source_db.in_transaction or source_db.execute("PRAGMA query_only").fetchone()[0] != 1
            or source_db.execute("PRAGMA user_version").fetchone()[0] != 2):
        raise Denied("PROBE_SOURCE_UNSUPPORTED", 503)
    _require(source_db, auth._session(source_db, token), resource_id, restart=True)
    original = _probe_audit(draft_db, resource_id, original_probe_id)
    if original is None or original != _probe_audit(source_db, resource_id, original_probe_id):
        raise Denied("PROBE_SOURCE_MISMATCH", 409)
    return original


def request_draft_probe(draft_db, queue, auth, token, csrf, draft_id, *, if_match, request_key):
    """Queue one read-only observation for this rehearsal revision and retry key."""
    row, draft = _checked_draft(draft_db, auth, token, draft_id, if_match)
    if not isinstance(request_key, str) or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", request_key) is None:
        raise Denied("IDEMPOTENCY_KEY_REQUIRED", 400)
    resource_id = row["resource_id"]
    baseline = draft["baseline"]
    with queue.store.connect(readonly=True) as source_db:
        source_db.execute("BEGIN")
        _probe_source(draft_db, source_db, auth, token, resource_id, baseline["observation_id"])
        resource = source_db.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
        if (resource is None or not resource["enabled"] or resource["revision"] != baseline["resource_revision"]
                or resource["policy_revision"] != baseline["policy_revision"] or resource["scope_digest"] != baseline["scope_digest"]):
            raise Denied("STALE_BASELINE", 409)
    if int(queue.clock()) <= row["created_at"]:
        raise Denied("NEW_PROBE_REQUIRED", 409)
    scoped_key = checksum({"purpose": "docker.restart.preflight", "plan_hash": row["plan_hash"], "key": request_key})
    return queue.enqueue_probe(auth, token, csrf, resource_id, scoped_key)


def check_draft_probe(draft_db, source_db, auth, token, draft_id, *, if_match, probe_id):
    """Validate a new queued observation on the Controller that supplied the rehearsal copy."""
    row, draft = _checked_draft(draft_db, auth, token, draft_id, if_match)
    resource_id = row["resource_id"]
    baseline = draft["baseline"]
    original = _probe_source(draft_db, source_db, auth, token, resource_id, baseline["observation_id"])
    checked_at = int(auth.clock())
    current = _baseline(source_db, resource_id, baseline["target"]["id"], checked_at)
    if probe_id != current["observation_id"] or probe_id == baseline["observation_id"]:
        raise Denied("NEW_PROBE_REQUIRED", 409)
    completed = _probe_audit(source_db, resource_id, probe_id)
    requested_at = source_db.execute("SELECT created_at FROM jobs WHERE id=?", (probe_id,)).fetchone()[0]
    if (completed is None or completed["seq"] <= original["seq"]
            or not row["created_at"] < requested_at <= current["observed_at"]):
        raise Denied("NEW_PROBE_REQUIRED", 409)
    if any(current[key] != baseline[key] for key in ("target", "boot_id", "scope_digest", "resource_revision", "policy_revision")):
        raise Denied("STALE_BASELINE", 409)
    # §33.3 exempts the read-only probe. Docker restart has no assigned gate class.
    return {"draft_id": row["id"], "revision": row["revision"], "plan_hash": row["plan_hash"],
            "observation_id": probe_id, "checked_at": checked_at, "baseline_check": "MATCHED",
            "backup_gate": "BACKUP_GATE_DENIED", "backup_gate_reason": "RESTART_BACKUP_POLICY_UNCLASSIFIED",
            "execution": draft["execution"]}


def save_draft(db, auth, token, csrf, resource_id, container_id, *, draft_id=None, if_match=None):
    """Create or refresh inside BEGIN IMMEDIATE. The caller rolls back on error."""
    actor = _session(db, auth, token, csrf=csrf, mutating=True)
    if re.fullmatch(ULID, resource_id) is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    _require(db, actor, resource_id, restart=True)
    if re.fullmatch(SHA256, container_id) is None:
        raise Denied("CONTAINER_NOT_FOUND", 404)
    revision = 1
    if draft_id is not None:
        row = _latest(db, draft_id)
        if row["resource_id"] != resource_id:
            raise Denied("RESOURCE_NOT_FOUND", 404)
        previous = _stored(row)
        if previous["baseline"]["target"]["id"] != container_id:
            raise Denied("RESOURCE_NOT_FOUND", 404)
        check_etag(if_match, _public(previous, row["plan_hash"])[1])
        revision = row["revision"] + 1
    else:
        draft_id = identifier()
    now = int(auth.clock())
    baseline = _baseline(db, resource_id, container_id, now)
    value = _value(draft_id, revision, baseline)
    plan_hash = checksum(value)
    db.execute("""INSERT INTO change_plan_drafts
                  (id,revision,actor_id,resource_id,action,baseline,plan_hash,created_at)
                  VALUES(?,?,?,?,?,?,?,?)""",
               (draft_id, revision, actor["id"], resource_id, value["action"], canonical(baseline).decode(),
                plan_hash, now))
    Store.event(db, at=now, actor=actor["id"], kind="change_plan.draft_saved", target=resource_id,
                outcome="SUCCEEDED", correlation=draft_id, details={"revision": revision, "plan_hash": plan_hash})
    return _public(value, plan_hash)
