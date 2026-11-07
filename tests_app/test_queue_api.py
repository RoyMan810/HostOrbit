from concurrent.futures import ThreadPoolExecutor

from hostorbit.auth import COOKIE
from hostorbit.queue import JobQueue
from hostorbit.errors import Denied
from test_auth_api import Fixture, SCOPE, OTHER


class QueueApiTests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        self.queue.register_resource(SCOPE, "a" * 64, 1)
        self.queue.register_resource(OTHER, "b" * 64, 1)

    def test_enqueue_requires_idempotency_and_commits_job_audit_outbox_before_202(self):
        endpoint = f"/api/v1/resources/{SCOPE}/observations"
        self.assertEqual(self.client.post(endpoint, json={}, headers=self.headers()).status_code, 403)
        response = self.client.post(endpoint, json={}, headers=self.headers(**{"Idempotency-Key": "fixture-request-0001"}))
        self.assertEqual(response.status_code, 202)
        result = response.json()
        self.assertEqual(result["status"], "QUEUED")
        self.assertEqual(self.client.get(response.headers["location"]).json()["id"], result["id"])
        events = self.store.events_after(0)
        self.assertTrue(any(e["event"]["details"].get("job_id") == result["id"] for e in events))
        self.store.verify_audit()

    def test_concurrent_idempotent_enqueue_has_one_job_and_payload_conflict(self):
        def enqueue(_):
            return self.queue.enqueue_probe(self.auth, self.client.cookies.get(COOKIE), self.csrf, SCOPE, "concurrent-key-0001")["id"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            ids = list(pool.map(enqueue, range(2)))
        self.assertEqual(ids[0], ids[1])
        with self.assertRaises(Denied) as caught:
            self.queue.enqueue_probe(self.auth, self.client.cookies.get(COOKIE), self.csrf, OTHER, "concurrent-key-0001")
        self.assertEqual(caught.exception.status, 409)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)

    def test_operator_cannot_probe_outside_scope_and_auditor_cannot_enqueue(self):
        self.create_user(grants=[{"permission": "vps:probe", "resource_id": SCOPE}, {"permission": "vps:read", "resource_id": SCOPE}])
        operator = self.other_client("operator")
        csrf = operator.get("/api/v1/auth/session").json()["csrf_token"]
        headers = {"Origin": "https://hostorbit.test", "X-CSRF-Token": csrf, "Idempotency-Key": "operator-request-0001"}
        self.assertEqual(operator.post(f"/api/v1/resources/{OTHER}/observations", json={}, headers=headers).status_code, 403)
        self.assertEqual(operator.post(f"/api/v1/resources/{SCOPE}/observations", json={}, headers=headers).status_code, 202)
        self.create_user(name="auditor", role="Auditor", grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        auditor = self.other_client("auditor")
        headers["X-CSRF-Token"] = auditor.get("/api/v1/auth/session").json()["csrf_token"]
        self.assertEqual(auditor.post(f"/api/v1/resources/{SCOPE}/observations", json={}, headers=headers).status_code, 403)
