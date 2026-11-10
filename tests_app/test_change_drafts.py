from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import json
import sqlite3

from hostorbit.auth import COOKIE, etag
from hostorbit.change_drafts import check_draft_baseline, check_draft_probe, get_draft, request_draft_probe, save_draft
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.migrations import rehearse
from hostorbit.queue import JobQueue
from hostorbit.runtime.protocol import canonical, checksum
from test_auth_api import Fixture, OTHER, SCOPE


CONTAINER = "c" * 64


class ChangeDraftTests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        self.queue.register_resource(SCOPE, "a" * 64, 1)
        self.probe_id = self.probe()
        self.token = self.client.cookies[COOKIE]
        self.output = self.directory / "rehearsal"
        rehearse(self.store, self.output, to_schema=3)

    def probe(self, outcome="SUCCEEDED", *, boot_id="11111111-1111-1111-1111-111111111111"):
        job = self.queue.enqueue_probe(self.auth, self.client.cookies[COOKIE], self.csrf, SCOPE, identifier())
        self.complete_probe(job["id"], outcome=outcome, boot_id=boot_id)
        return job["id"]

    def complete_probe(self, job_id, *, outcome="SUCCEEDED", boot_id="11111111-1111-1111-1111-111111111111"):
        claim, row = self.queue.claim(identifier())
        self.assertEqual(row["id"], job_id)
        self.queue.advance(claim, "INTENT_PREPARED", permit={"claims": self.queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            self.queue.advance(claim, state)
        result = {"status": "REACHABLE", "source": "restricted_helper", "observed_at": self.now,
                  "boot_id": boot_id,
                  "software": {"docker": "PRESENT", "nginx": "UNKNOWN"},
                  "docker": {"status": "OBSERVED", "containers": [
                      {"id": CONTAINER, "project": "fixture", "service": "web", "state": "RUNNING"},
                  ]}}
        self.queue.finish(claim, outcome, "PROBE_COMPLETE" if outcome == "SUCCEEDED" else "SSH_TIMEOUT",
                          result=result if outcome == "SUCCEEDED" else None)

    @contextmanager
    def transaction(self, *, write=True):
        with closing(sqlite3.connect(self.output / "migrated.sqlite3", autocommit=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            if not write:
                db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.execute("COMMIT")

    def save(self, **kwargs):
        with self.transaction() as db:
            return save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER, **kwargs)

    def test_persists_exact_observation_and_audit_without_creating_a_job(self):
        value, tag = self.save()
        self.assertEqual(value["state"], "DRAFT")
        self.assertEqual(value["baseline"]["observation_id"], self.probe_id)
        self.assertEqual(value["backup_gate"], "NOT_EVALUATED")
        self.assertEqual(value["execution"], "BLOCKED")
        self.assertNotIn("scope_digest", value["baseline"])
        with self.transaction(write=False) as db:
            self.assertEqual(get_draft(db, self.auth, self.token, value["id"]), (value, tag))
            stored = db.execute("SELECT baseline FROM change_plan_drafts").fetchone()[0]
            bound = dict(value)
            del bound["plan_hash"]
            bound["baseline"] = json.loads(stored)
            self.assertEqual(value["plan_hash"], checksum(bound))
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT event FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0],
                             "change_plan.draft_saved")
            Store.verify_audit_connection(db)

    def test_pins_latest_completed_job_even_when_probe_timestamps_match(self):
        newest = self.probe()
        self.assertNotEqual(newest, self.probe_id)
        self.output = self.directory / "latest"
        rehearse(self.store, self.output, to_schema=3)
        self.assertEqual(self.save()[0]["baseline"]["observation_id"], newest)
        self.probe("FAILED")
        self.output = self.directory / "failed"
        rehearse(self.store, self.output, to_schema=3)
        with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
            self.save()

    def test_rechecks_scoped_permissions_on_every_revision(self):
        self.create_user(grants=[{"permission": permission, "resource_id": SCOPE}
                                 for permission in ("vps:read", "vps:restart")])
        client = self.other_client("operator")
        token = client.cookies[COOKIE]
        csrf = client.get("/api/v1/auth/session").json()["csrf_token"]
        self.output = self.directory / "scoped"
        rehearse(self.store, self.output, to_schema=3)
        with self.transaction() as db:
            draft, tag = save_draft(db, self.auth, token, csrf, SCOPE, CONTAINER)
            db.execute("DELETE FROM grants WHERE permission='vps:restart'")
        with self.assertRaisesRegex(Denied, "FORBIDDEN"):
            with self.transaction() as db:
                save_draft(db, self.auth, token, csrf, SCOPE, CONTAINER, draft_id=draft["id"], if_match=tag)
        with self.transaction() as db:
            self.assertEqual(get_draft(db, self.auth, token, draft["id"])[0]["revision"], 1)
            db.execute("DELETE FROM grants WHERE permission='vps:read'")
        with self.assertRaisesRegex(Denied, "RESOURCE_NOT_FOUND"):
            with self.transaction(write=False) as db:
                get_draft(db, self.auth, token, draft["id"])

    def test_concurrent_revision_requires_exact_strong_etag(self):
        value, tag = self.save()
        with self.assertRaisesRegex(Denied, "IF_MATCH_REQUIRED"):
            self.save(draft_id=value["id"])
        with self.assertRaisesRegex(Denied, "STALE_REVISION"):
            self.save(draft_id=value["id"], if_match="W/" + tag)

        def refresh(_):
            try:
                return self.save(draft_id=value["id"], if_match=tag)[0]["revision"]
            except Denied as error:
                return error.status

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(refresh, (1, 2)), (2, 412))
        with self.transaction(write=False) as db:
            self.assertEqual([row[0] for row in db.execute("SELECT revision FROM change_plan_drafts ORDER BY revision")], [1, 2])

    def test_refuses_expired_observation_bad_csrf_and_cross_target_refresh(self):
        with self.transaction() as db:
            with self.assertRaisesRegex(Denied, "CSRF_REQUIRED"):
                save_draft(db, self.auth, self.token, "invalid", SCOPE, CONTAINER)
        value, tag = self.save()
        with self.transaction() as db:
            with self.assertRaisesRegex(Denied, "RESOURCE_NOT_FOUND"):
                save_draft(db, self.auth, self.token, self.csrf, OTHER, CONTAINER,
                           draft_id=value["id"], if_match=tag)
        self.now += 301
        with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
            self.save(draft_id=value["id"], if_match=tag)
        with self.transaction(write=False) as db:
            self.assertEqual(get_draft(db, self.auth, self.token, value["id"])[0]["revision"], 1)

    def test_failed_audit_write_rolls_back_draft(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.transaction() as db:
                db.execute("""CREATE TEMP TRIGGER fixture_outbox_failure BEFORE INSERT ON outbox
                              BEGIN SELECT RAISE(ABORT, 'fixture outbox unavailable'); END""")
                save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER)
        with self.transaction(write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM change_plan_drafts").fetchone()[0], 0)
            Store.verify_audit_connection(db)

    def test_live_schema_two_rejects_draft_writes(self):
        with self.assertRaisesRegex(Denied, "CHANGE_PLAN_SCHEMA_REQUIRES_VERIFIED_MIGRATION"):
            with self.store.write() as db:
                save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER)

    def test_checks_exact_draft_without_writes_or_execution_authority(self):
        draft, tag = self.save()
        with self.transaction(write=False) as db:
            self.assertEqual(check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag), {
                "draft_id": draft["id"], "revision": 1, "plan_hash": draft["plan_hash"],
                "observation_id": self.probe_id, "checked_at": self.now,
                "baseline_check": "MATCHED", "backup_gate": "NOT_EVALUATED", "execution": "BLOCKED",
            })
            with self.assertRaisesRegex(Denied, "IF_MATCH_REQUIRED"):
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=None)
        self.save(draft_id=draft["id"], if_match=tag)
        with self.transaction(write=False) as db:
            with self.assertRaisesRegex(Denied, "STALE_REVISION"):
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag)

    def test_baseline_check_rejects_changed_resource_and_expired_observation(self):
        draft, tag = self.save()
        with self.transaction() as db:
            db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (SCOPE,))
            with self.assertRaisesRegex(Denied, "STALE_BASELINE") as error:
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag)
            self.assertEqual(error.exception.status, 409)
            db.execute("UPDATE resources SET revision=revision-1 WHERE id=?", (SCOPE,))
        self.now += 301
        with self.transaction(write=False) as db:
            with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag)

    def test_baseline_check_rejects_new_probe_with_identical_observation_data(self):
        draft, tag = self.save()
        replacement = identifier()
        with self.transaction() as db:
            # The live queue cannot write schema 3. Replay the completed job
            # and its audit marker in the rehearsal fixture.
            db.execute("""INSERT INTO jobs(id,actor_id,resource_id,action,payload_hash,scope_digest,policy_revision,
                                           status,revision,result,reason,created_at,updated_at)
                          SELECT ?,actor_id,resource_id,action,payload_hash,scope_digest,policy_revision,
                                 status,revision,result,reason,created_at,updated_at FROM jobs WHERE id=?""",
                       (replacement, self.probe_id))
            Store.event(db, at=self.now, actor=self.owner, kind="job.finished", target=SCOPE,
                        outcome="SUCCEEDED", correlation=replacement)
        with self.transaction(write=False) as db:
            with self.assertRaisesRegex(Denied, "STALE_BASELINE"):
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag)

    def test_baseline_check_denies_revoked_restart_and_tampered_plan(self):
        self.create_user(grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        observer = self.other_client("operator").cookies[COOKIE]
        self.output = self.directory / "read-only-operator"
        rehearse(self.store, self.output, to_schema=3)
        draft, tag = self.save()
        with self.transaction(write=False) as db:
            with self.assertRaisesRegex(Denied, "FORBIDDEN"):
                check_draft_baseline(db, self.auth, observer, draft["id"], if_match=tag)
        with self.transaction() as db:
            db.execute("UPDATE change_plan_drafts SET plan_hash=? WHERE id=?", ("0" * 64, draft["id"]))
        with self.transaction(write=False) as db:
            with self.assertRaisesRegex(Denied, "CHANGE_PLAN_INTEGRITY"):
                check_draft_baseline(db, self.auth, self.token, draft["id"], if_match=tag)

    def check_probe(self, draft, tag, probe_id, *, key="preflight-request-one"):
        with self.transaction(write=False) as draft_db, self.store.connect(readonly=True) as source_db:
            source_db.execute("BEGIN")
            return check_draft_probe(draft_db, source_db, self.auth, self.token, draft["id"],
                                     if_match=tag, probe_id=probe_id, request_key=key)

    def test_probe_check_requires_fresh_job_from_the_source_controller(self):
        draft, tag = self.save()
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(draft, tag, self.probe_id)
        self.now += 1
        fresh = self.request_probe(draft, tag)["id"]
        self.complete_probe(fresh)
        result = self.check_probe(draft, tag, fresh)
        self.assertEqual(result["observation_id"], fresh)
        self.assertEqual(result["plan_hash"], draft["plan_hash"])
        self.assertEqual(result["execution"], "BLOCKED")
        self.assertEqual(result["backup_gate"], "BACKUP_GATE_DENIED")
        self.assertEqual(result["backup_gate_reason"], "RESTART_BACKUP_POLICY_UNCLASSIFIED")
        self.now += 1
        self.probe("FAILED")
        with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
            self.check_probe(draft, tag, fresh)

    def test_probe_check_rejects_a_fresh_generic_probe_of_the_same_vps(self):
        draft, tag = self.save()
        self.now += 1
        unrelated = self.probe()
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(draft, tag, unrelated)

    def test_generic_queue_cannot_forge_a_draft_probe_key_from_public_fields(self):
        draft, tag = self.save()
        self.assertNotIn("probe_nonce", draft["baseline"])
        self.now += 1
        key = "preflight-request-one"
        forged = checksum({"purpose": "docker.restart.preflight", "plan_hash": draft["plan_hash"], "key": key})
        unrelated = self.queue.enqueue_probe(self.auth, self.token, self.csrf, SCOPE, forged)["id"]
        self.complete_probe(unrelated)
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(draft, tag, unrelated, key=key)
        self.assertNotEqual(self.request_probe(draft, tag, key=key)["id"], unrelated)

    def test_legacy_draft_requires_refresh_for_new_probe_binding(self):
        draft, _ = self.save()
        with self.transaction() as db:
            baseline = json.loads(db.execute("SELECT baseline FROM change_plan_drafts").fetchone()[0])
            del baseline["probe_nonce"]
            value = {key: item for key, item in draft.items() if key != "plan_hash"}
            digest = checksum({**value, "baseline": baseline})
            db.execute("UPDATE change_plan_drafts SET baseline=?, plan_hash=?",
                       (canonical(baseline).decode(), digest))
        legacy = {**value, "plan_hash": digest}
        tag = etag(legacy, legacy["revision"])
        with self.transaction(write=False) as db:
            self.assertEqual(get_draft(db, self.auth, self.token, legacy["id"]), (legacy, tag))
            self.assertEqual(check_draft_baseline(db, self.auth, self.token, legacy["id"], if_match=tag)
                             ["baseline_check"], "MATCHED")
        self.now += 1
        with self.assertRaisesRegex(Denied, "PREFLIGHT_DRAFT_REFRESH_REQUIRED"):
            self.request_probe(legacy, tag)
        updated, updated_tag = self.save(draft_id=legacy["id"], if_match=tag)
        self.now += 1
        self.assertEqual(self.request_probe(updated, updated_tag)["status"], "QUEUED")

    def test_probe_check_rejects_reboot_or_diverged_source_audit(self):
        draft, tag = self.save()
        self.now += 1
        fresh = self.request_probe(draft, tag)["id"]
        self.complete_probe(fresh, boot_id="22222222-2222-2222-2222-222222222222")
        with self.assertRaisesRegex(Denied, "STALE_BASELINE"):
            self.check_probe(draft, tag, fresh)
        with self.transaction() as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET digest=? WHERE event='job.finished' AND correlation_id=?",
                       ("0" * 64, self.probe_id))
        with self.assertRaisesRegex(Denied, "PROBE_SOURCE_MISMATCH"):
            self.check_probe(draft, tag, fresh)

    def test_probe_check_rejects_other_revision_wrong_key_and_expired_binding(self):
        draft, tag = self.save()
        self.now += 1
        job = self.request_probe(draft, tag)["id"]
        self.complete_probe(job)
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(draft, tag, job, key="preflight-request-two")
        revised, revised_tag = self.save(draft_id=draft["id"], if_match=tag)
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(revised, revised_tag, job)
        self.now += 1
        current_job = self.request_probe(revised, revised_tag)["id"]
        self.complete_probe(current_job)
        with self.store.write() as db:
            db.execute("UPDATE request_keys SET expires_at=? WHERE job_id=?", (self.now, current_job))
        with self.assertRaisesRegex(Denied, "PREFLIGHT_PROBE_NOT_BOUND"):
            self.check_probe(revised, revised_tag, current_job)

    def request_probe(self, draft, tag, *, key="preflight-request-one", csrf=None):
        with self.transaction(write=False) as db:
            return request_draft_probe(db, self.queue, self.auth, self.token, self.csrf if csrf is None else csrf,
                                       draft["id"], if_match=tag, request_key=key)

    def test_probe_request_reuses_one_queued_job_and_can_check_its_result(self):
        draft, tag = self.save()
        self.now += 1
        job = self.request_probe(draft, tag)
        self.assertEqual((job["action"], job["status"], job["resource_id"]), ("host.probe", "QUEUED", SCOPE))
        self.assertEqual(self.request_probe(draft, tag)["id"], job["id"])
        self.complete_probe(job["id"])
        preflight = self.check_probe(draft, tag, job["id"])
        self.assertEqual(preflight["baseline_check"], "MATCHED")
        self.assertEqual(preflight["backup_gate"], "BACKUP_GATE_DENIED")
        self.assertEqual(preflight["execution"], "BLOCKED")
        revised, revised_tag = self.save(draft_id=draft["id"], if_match=tag)
        self.now += 1
        self.assertNotEqual(self.request_probe(revised, revised_tag)["id"], job["id"])

    def test_probe_request_refuses_invalid_inputs_and_stale_scope_before_enqueue(self):
        draft, tag = self.save()
        with self.assertRaisesRegex(Denied, "NEW_PROBE_REQUIRED"):
            self.request_probe(draft, tag)
        self.now += 1
        for args, reason in (({"csrf": "bad"}, "CSRF_REQUIRED"), ({"key": "short"}, "IDEMPOTENCY_KEY_REQUIRED")):
            with self.subTest(reason=reason), self.assertRaisesRegex(Denied, reason):
                self.request_probe(draft, tag, **args)
        with self.assertRaisesRegex(Denied, "STALE_REVISION"):
            self.request_probe(draft, '"wrong"')
        with self.store.write() as db:
            db.execute("UPDATE resources SET policy_revision=policy_revision+1 WHERE id=?", (SCOPE,))
        with self.assertRaisesRegex(Denied, "STALE_BASELINE"):
            self.request_probe(draft, tag)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
