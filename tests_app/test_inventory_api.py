from unittest.mock import patch

from fastapi.testclient import TestClient

from hostorbit.database import identifier
from hostorbit.queue import JobQueue
from hostorbit.runtime.protocol import checksum
from test_auth_api import Fixture, OTHER, SCOPE


CONTAINER = "c" * 64
RUNNING_DOCKER = {"status": "OBSERVED", "containers": [
    {"id": CONTAINER, "project": "fixture", "service": "web", "state": "RUNNING"},
]}


class InventoryTests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        for resource in (SCOPE, OTHER):
            self.queue.register_resource(resource, "a" * 64, 1)

    def detail(self, resource=SCOPE):
        response = self.client.get(f"/api/v1/resources/{resource}")
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def complete(self, outcome="SUCCEEDED", reason="PROBE_COMPLETE", *, docker=None):
        self.now += 1
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": identifier()}))
        self.assertEqual(response.status_code, 202, response.text)
        claim, row = self.queue.claim(identifier())
        self.queue.advance(claim, "INTENT_PREPARED", permit={"claims": self.queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            self.queue.advance(claim, state)
        value = {"status": "REACHABLE", "source": "restricted_helper", "observed_at": self.now,
                 "boot_id": "11111111-1111-1111-1111-111111111111"}
        if docker is not None:
            value.update(software={"docker": "PRESENT", "nginx": "UNKNOWN"}, docker=docker)
        self.queue.finish(claim, outcome, reason, result=value if outcome == "SUCCEEDED" else None)
        return response.json()["id"]

    def restart_preview(self, *, resource=SCOPE, container=CONTAINER, client=None):
        return (client or self.client).get(
            f"/api/v1/resources/{resource}/docker/containers/{container}/restart-preview"
        )

    def test_restart_preview_is_bound_to_a_fresh_observation_and_creates_no_work(self):
        self.complete(docker=RUNNING_DOCKER)
        before = self.store.verify_audit()
        response = self.restart_preview()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        result = response.json()
        digest = result.pop("preview_digest")
        self.assertEqual(digest, checksum(result))
        self.assertEqual(result["action"], "docker.restart")
        self.assertEqual(result["status"], "PREVIEW_ONLY")
        self.assertEqual(result["target"], {"resource_id": SCOPE, **RUNNING_DOCKER["containers"][0]})
        self.assertEqual(result["observed_at"], self.now)
        self.assertEqual(self.restart_preview().json()["preview_digest"], digest)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
        self.assertEqual(self.store.verify_audit(), before)
        self.complete(docker=RUNNING_DOCKER)
        self.assertNotEqual(self.restart_preview().json()["preview_digest"], digest)

    def test_restart_preview_requires_read_and_restart_in_the_same_scope(self):
        self.complete(docker=RUNNING_DOCKER)
        read = {"permission": "vps:read", "resource_id": SCOPE}
        restart = {"permission": "vps:restart", "resource_id": SCOPE}
        self.create_user(name="scoped", grants=[read, restart])
        scoped = self.other_client("scoped")
        self.assertEqual(self.restart_preview(client=scoped).status_code, 200)
        self.assertEqual(self.restart_preview(resource=OTHER, client=scoped).status_code, 404)
        self.create_user(name="split", grants=[read, {**restart, "resource_id": OTHER}])
        self.assertEqual(self.restart_preview(client=self.other_client("split")).status_code, 403)
        self.create_user(name="observer", role="Auditor", grants=[read])
        self.assertEqual(self.restart_preview(client=self.other_client("observer")).status_code, 403)
        with self.store.write() as db:
            db.execute("DELETE FROM grants WHERE permission='vps:restart'")
        self.assertEqual(self.restart_preview(client=scoped).status_code, 403)

    def test_restart_preview_rejects_stale_unavailable_or_ineligible_container(self):
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete()
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete(docker=RUNNING_DOCKER)
        self.assertEqual(self.restart_preview(container=CONTAINER[:12]).status_code, 404)
        self.assertEqual(self.restart_preview(container="f" * 64).status_code, 404)
        self.now += 301
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete(docker={"status": "UNAVAILABLE", "containers": []})
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete(docker={"status": "OBSERVED", "containers": [
            {**RUNNING_DOCKER["containers"][0], "state": "EXITED"},
        ]})
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete(docker=RUNNING_DOCKER)
        self.complete("FAILED", "SSH_TIMEOUT")
        self.assertEqual(self.restart_preview().status_code, 409)
        self.complete(docker=RUNNING_DOCKER)
        with self.store.write() as db:
            db.execute("UPDATE resources SET policy_revision=2 WHERE id=?", (SCOPE,))
        self.assertEqual(self.restart_preview().status_code, 409)

    def test_inventory_never_claims_health_or_creates_work_before_a_probe(self):
        before = self.store.verify_audit()
        response = self.client.get("/api/v1/resources")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([v["id"] for v in response.json()["items"]], [SCOPE, OTHER])
        item = self.detail().json()
        self.assertEqual(item["observation"], {"status": "NOT_CHECKED", "reason": "NO_COMPLETED_OBSERVATION",
                                              "last_checked_at": None, "last_success": None})
        self.assertEqual(item["access_mode"], "READ_ONLY")
        self.assertTrue(item["enabled"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("etag", response.headers)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(self.store.verify_audit(), before)

    def test_scope_is_filtered_before_pagination_and_foreign_detail_is_hidden(self):
        self.create_user(grants=[{"permission": "vps:read", "resource_id": OTHER}])
        operator = self.other_client("operator")
        response = operator.get("/api/v1/resources?limit=1")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([v["id"] for v in response.json()["items"]], [OTHER])
        self.assertIsNone(response.json()["next_after"])
        for identity in (SCOPE, identifier(), "invalid"):
            self.assertEqual(operator.get(f"/api/v1/resources/{identity}").status_code, 404)
        with self.store.write() as db:
            db.execute("DELETE FROM grants WHERE permission='vps:read'")
        self.assertEqual(operator.get("/api/v1/resources").json()["items"], [])
        self.assertEqual(operator.get(f"/api/v1/resources/{OTHER}").status_code, 404)

    def test_auditor_wildcard_and_scoped_admin_use_the_same_read_permission(self):
        self.create_user(name="auditor", role="Auditor", grants=[{"permission": "vps:read", "resource_id": "*"}])
        auditor = self.other_client("auditor")
        self.assertEqual(len(auditor.get("/api/v1/resources").json()["items"]), 2)
        self.create_user(name="admin", role="Admin", grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        admin = self.other_client("admin")
        self.assertEqual([v["id"] for v in admin.get("/api/v1/resources").json()["items"]], [SCOPE])

    def test_pagination_validation_and_unauthenticated_access(self):
        first = self.client.get("/api/v1/resources?limit=1").json()
        self.assertEqual([v["id"] for v in first["items"]], [SCOPE])
        self.assertEqual(first["next_after"], SCOPE)
        last = self.client.get(f"/api/v1/resources?limit=1&after={SCOPE}").json()
        self.assertEqual([v["id"] for v in last["items"]], [OTHER])
        self.assertIsNone(last["next_after"])
        for query in ("limit=0", "limit=101", "limit=x", "after=secret-canary"):
            response = self.client.get("/api/v1/resources?" + query)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("secret-canary", response.text)
        with TestClient(self.client.app, base_url="https://hostorbit.test") as anonymous:
            for url in ("/api/v1/resources", f"/api/v1/resources/{SCOPE}"):
                self.assertEqual(anonymous.get(url).status_code, 401)

    def test_freshness_and_clock_rollback_change_status_and_etag(self):
        self.complete()
        fresh = self.detail()
        observation = fresh.json()["observation"]
        self.assertEqual(observation["status"], "REACHABLE")
        self.assertEqual(observation["last_checked_at"], self.now)
        self.assertEqual(observation["last_success"]["source"], "restricted_helper")
        self.now += 300
        self.assertEqual(self.detail().json()["observation"]["status"], "REACHABLE")
        self.now += 1
        stale = self.detail()
        self.assertEqual(stale.json()["observation"]["reason"], "OBSERVATION_STALE")
        self.assertEqual(stale.json()["observation"]["status"], "UNKNOWN")
        self.assertNotEqual(stale.headers["etag"], fresh.headers["etag"])
        # Keep session time valid while simulating a remote sample from the future.
        with self.store.write() as db:
            db.execute("UPDATE jobs SET result=json_set(result,'$.observed_at',?)", (self.now + 1,))
        self.assertEqual(self.detail().json()["observation"]["reason"], "OBSERVATION_TIME_INVALID")

    def test_failed_or_unknown_latest_attempt_does_not_reuse_old_success_as_current(self):
        self.complete()
        previous = self.detail().json()["observation"]["last_success"]
        for outcome in ("FAILED", "UNKNOWN_OUTCOME"):
            self.complete(outcome, "SSH_TIMEOUT")
            value = self.detail().json()["observation"]
            self.assertEqual(value["status"], "UNKNOWN")
            self.assertEqual(value["reason"], "SSH_TIMEOUT")
            self.assertEqual(value["last_success"], previous)
            self.assertEqual(value["last_checked_at"], self.now)

    def test_pending_job_does_not_hide_completed_observation(self):
        self.complete()
        before = self.detail().json()["observation"]
        self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                         headers=self.headers(**{"Idempotency-Key": identifier()}))
        self.assertEqual(self.detail().json()["observation"], before)

    def test_changed_scope_disabled_and_untrusted_result_fields_are_not_current(self):
        job = self.complete()
        with self.store.write() as db:
            db.execute("UPDATE jobs SET result=json_set(result,'$.private_key','secret-canary') WHERE id=?", (job,))
        self.assertNotIn("secret-canary", self.detail().text)
        with self.store.write() as db:
            db.execute("UPDATE resources SET scope_digest=? WHERE id=?", ("b" * 64, SCOPE))
        changed = self.detail().json()["observation"]
        self.assertEqual(changed["status"], "UNKNOWN")
        self.assertEqual(changed["reason"], "OBSERVATION_SCOPE_CHANGED")
        self.assertIsNone(changed["last_success"])
        with self.store.write() as db:
            db.execute("UPDATE resources SET enabled=0 WHERE id=?", (SCOPE,))
        disabled = self.detail().json()
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["observation"]["reason"], "RESOURCE_DISABLED")

    def test_schema_one_is_not_silently_migrated(self):
        with self.store.write() as db:
            db.execute("PRAGMA user_version=1")
        for url in ("/api/v1/resources", f"/api/v1/resources/{SCOPE}"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 503)
        with self.store.read() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_equal_creation_times_use_completion_order_for_latest_and_last_success(self):
        with patch('hostorbit.queue.identifier', side_effect=[OTHER, SCOPE]):
            self.complete(docker=RUNNING_DOCKER)
            self.now -= 1
            self.complete('FAILED', 'SSH_TIMEOUT')
        observation = self.detail().json()['observation']
        self.assertEqual(observation['reason'], 'SSH_TIMEOUT')
        self.assertIsNotNone(observation['last_success'])
        self.assertEqual(self.restart_preview().status_code, 409)

        with patch('hostorbit.queue.identifier', side_effect=['01JCYQZ4T9V8MNVYEH3D2M7Q1D', '01JCYQZ4T9V8MNVYEH3D2M7Q1C']):
            self.complete(docker=RUNNING_DOCKER)
            self.now -= 1
            self.complete(docker={'status': 'UNAVAILABLE', 'containers': []})
        observation = self.detail().json()['observation']
        self.assertEqual(observation['status'], 'REACHABLE')
        self.assertEqual(observation['last_success']['docker']['status'], 'UNAVAILABLE')
        self.assertEqual(self.restart_preview().status_code, 409)

    def test_quarantined_job_without_finish_event_is_visible(self):
        self.complete()
        self.client.post(f'/api/v1/resources/{SCOPE}/observations', json={},
                         headers=self.headers(**{'Idempotency-Key': identifier()}))
        with self.store.write() as db:
            db.execute("UPDATE jobs SET status='CANCELLED_SAFE',reason='RESTORE_QUARANTINE' WHERE status='QUEUED'")
        observation = self.detail().json()['observation']
        self.assertEqual(observation['status'], 'UNKNOWN')
        self.assertEqual(observation['reason'], 'RESTORE_QUARANTINE')
        self.assertIsNotNone(observation['last_success'])

    def test_policy_revision_change_alone_invalidates_the_success(self):
        self.complete()
        with self.store.write() as db:
            db.execute('UPDATE resources SET policy_revision=2 WHERE id=?', (SCOPE,))
        value = self.detail().json()['observation']
        self.assertEqual(value['reason'], 'OBSERVATION_SCOPE_CHANGED')
        self.assertIsNone(value['last_success'])

    def test_cancelled_safe_does_not_claim_the_host_is_reachable(self):
        self.client.post(f'/api/v1/resources/{SCOPE}/observations', json={},
                         headers=self.headers(**{'Idempotency-Key': identifier()}))
        claim, _ = self.queue.claim(identifier())
        self.queue.finish(claim, 'CANCELLED_SAFE', 'ACTOR_REVOKED')
        value = self.detail().json()['observation']
        self.assertEqual(value['status'], 'UNKNOWN')
        self.assertEqual(value['reason'], 'ACTOR_REVOKED')

    def test_invalid_success_data_or_future_completion_is_unknown(self):
        job = self.complete()
        with self.store.write() as db:
            db.execute('UPDATE jobs SET updated_at=? WHERE id=?', (self.now + 1, job))
        self.assertEqual(self.detail().json()['observation']['reason'], 'OBSERVATION_TIME_INVALID')
        with self.store.write() as db:
            db.execute('UPDATE jobs SET result=? WHERE id=?', ('{"status":"REACHABLE"}', job))
        value = self.detail().json()['observation']
        self.assertEqual(value['reason'], 'OBSERVATION_INVALID')
        self.assertIsNone(value['last_success'])
