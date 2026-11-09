from concurrent.futures import ThreadPoolExecutor
import os

from hostorbit.admission import Admission
from hostorbit.database import identifier

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

    def test_closing_returns_retryable_503_for_new_jobs_but_keeps_authenticated_reads(self):
        writers = Admission.initialize(self.directory / "writers", owner=os.geteuid())
        self.store.writers = writers
        writers.publish("CLOSING_ADMISSION", identifier())
        self.assertEqual(self.client.get("/api/v1/users").status_code, 200)
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": "closing-request-0001"}))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["retry-after"], "1")
        self.assertEqual(response.json()["code"], "WRITER_ADMISSION_CLOSED")
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
        self.store.verify_audit()

    def test_enqueue_requires_idempotency_and_commits_job_audit_outbox_before_202(self):
        endpoint = f"/api/v1/resources/{SCOPE}/observations"
        self.assertEqual(self.client.post(endpoint, json={}, headers=self.headers()).status_code, 400)
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

    def test_timeline_is_scoped_ordered_and_contains_only_safe_job_fields(self):
        endpoint = f"/api/v1/resources/{SCOPE}/observations"
        response = self.client.post(endpoint, json={}, headers=self.headers(**{"Idempotency-Key": "timeline-request-01"}))
        job_id = response.json()["id"]
        claim, row = self.queue.claim(identifier())
        self.queue.advance(claim, "INTENT_PREPARED", permit={"claims": self.queue.binding(row)})
        self.queue.advance(claim, "DISPATCHING")
        self.queue.finish(claim, "UNKNOWN_OUTCOME", "SSH_TIMEOUT")
        with self.store.write() as db:
            self.store.event(db, at=self.now, actor="fixture", kind="job.finished", target=OTHER,
                             outcome="FAILED", correlation=job_id, details={"job_id": job_id, "reason": "OTHER_TARGET"})
        self.create_user(name="reader", role="Auditor", grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        reader = self.other_client("reader")
        path = f"/api/v1/jobs/{job_id}/timeline"
        result = reader.get(path)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.headers["cache-control"], "no-store")
        items = result.json()["items"]
        self.assertEqual([item["status"] for item in items], ["QUEUED", "INTENT_PREPARED", "DISPATCHING", "UNKNOWN_OUTCOME"])
        self.assertEqual(items[-1]["reason"], "SSH_TIMEOUT")
        self.assertEqual(sorted(item["seq"] for item in items), [item["seq"] for item in items])
        self.assertTrue(all(set(item) == {"seq", "at", "status", "reason"} for item in items))
        foreign = self.client.post(f"/api/v1/resources/{OTHER}/observations", json={},
                                   headers=self.headers(**{"Idempotency-Key": "timeline-foreign-01"})).json()["id"]
        self.assertEqual(reader.get(f"/api/v1/jobs/{foreign}/timeline").status_code, 404)
        self.assertEqual(reader.get(f"/api/v1/jobs/{identifier()}/timeline").status_code, 404)
        with self.store.write() as db:
            db.execute("DELETE FROM grants WHERE permission='vps:read' AND resource_id=?", (SCOPE,))
        self.assertEqual(reader.get(path).status_code, 404)

    def test_timeline_rejects_invalid_stored_event_instead_of_claiming_a_status(self):
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": "timeline-invalid-01"}))
        job_id = response.json()["id"]
        with self.store.write() as db:
            self.store.event(db, at=self.now, actor="fixture", kind="job.finished", target=SCOPE,
                             outcome="SUCCEEDED", correlation=job_id,
                             details={"job_id": job_id, "reason": "unsafe secret"})
        result = self.client.get(f"/api/v1/jobs/{job_id}/timeline")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.json()["code"], "JOB_TIMELINE_INVALID")

    def test_timeline_rejects_unconfirmed_success_and_missing_audit_transition(self):
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": "timeline-unconfirmed-01"}))
        job_id = response.json()["id"]
        path = f"/api/v1/jobs/{job_id}/timeline"
        with self.store.write() as db:
            self.store.event(db, at=self.now, actor="fixture", kind="job.finished", target=SCOPE,
                             outcome="SUCCEEDED", correlation=job_id,
                             details={"job_id": job_id, "revision": 2, "reason": "PROBE_VERIFIED"})
        self.assertEqual(self.client.get(path).json()["code"], "JOB_TIMELINE_INVALID")
        other = self.client.post(f"/api/v1/resources/{OTHER}/observations", json={},
                                 headers=self.headers(**{"Idempotency-Key": "timeline-missing-01"})).json()["id"]
        with self.store.write() as db:
            db.execute("UPDATE jobs SET revision=revision+1,status='DISPATCHING' WHERE id=?", (other,))
        self.assertEqual(self.client.get(f"/api/v1/jobs/{other}/timeline").json()["code"], "JOB_TIMELINE_INVALID")

    def test_timeline_rejects_truncated_history(self):
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": "timeline-limit-0001"}))
        job_id = response.json()["id"]
        with self.store.write() as db:
            for _ in range(100):
                self.store.event(db, at=self.now, actor="fixture", kind="job.transition", target=SCOPE,
                                 outcome="EXECUTING", correlation=job_id,
                                 details={"job_id": job_id, "reason": None})
        result = self.client.get(f"/api/v1/jobs/{job_id}/timeline")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.json()["code"], "JOB_TIMELINE_INVALID")

    def test_schema_one_keeps_auth_and_blocks_queue_without_automatic_migration(self):
        with self.store.connect() as db:
            db.execute("PRAGMA user_version=1")
        self.assertEqual(self.client.get("/api/v1/users").status_code, 200)
        response = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                    headers=self.headers(**{"Idempotency-Key": "legacy-request-0001"}))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "QUEUE_SCHEMA_REQUIRES_VERIFIED_MIGRATION")
        with self.store.connect() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM users").fetchone()[0], 1)
