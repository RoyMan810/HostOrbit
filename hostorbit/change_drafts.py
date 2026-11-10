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


def _require(db, actor, resource_id, *, mutating):
    try:
        AuthService.require(db, actor, "vps:read", resource_id)
    except Denied:
        raise Denied("RESOURCE_NOT_FOUND", 404) from None
    if mutating:
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
    _require(db, actor, row["resource_id"], mutating=False)
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


def save_draft(db, auth, token, csrf, resource_id, container_id, *, draft_id=None, if_match=None):
    """Create or refresh inside BEGIN IMMEDIATE. The caller rolls back on error."""
    actor = _session(db, auth, token, csrf=csrf, mutating=True)
    if re.fullmatch(ULID, resource_id) is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    _require(db, actor, resource_id, mutating=True)
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
