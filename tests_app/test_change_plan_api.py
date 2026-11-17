from hostorbit.database import identifier
from hostorbit.queue import JobQueue
from test_auth_api import Fixture, PASSWORD, SCOPE


CONTAINER = "c" * 64
REQUEST_KEY = "fixture-preflight-001"


class ChangePlanAPITests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=self.auth.clock)
        self.queue.register_resource(SCOPE, "a" * 64, 1)

    def complete_probe(self, job):
        claim, row = self.queue.claim(identifier())
        self.assertEqual(row["id"], job)
        self.queue.advance(claim, "INTENT_PREPARED", permit={"claims": self.queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            self.queue.advance(claim, state)
        self.queue.finish(claim, "SUCCEEDED", "PROBE_VERIFIED", result={
            "status": "REACHABLE", "source": "restricted_helper", "observed_at": self.now,
            "boot_id": "11111111-1111-1111-1111-111111111111",
            "software": {"docker": "PRESENT", "nginx": "UNKNOWN"},
            "docker": {"status": "OBSERVED", "containers": [{
                "id": CONTAINER, "project": "fixture", "service": "web", "state": "RUNNING",
                "mount_status": "NONE", "network_status": "ISOLATED",
                "dependency_status": "ISOLATED", "published_ports": [],
            }]},
        })

    def draft(self):
        source = self.client.post(f"/api/v1/resources/{SCOPE}/observations", json={},
                                  headers=self.headers(**{"Idempotency-Key": identifier()}))
        self.assertEqual(source.status_code, 202, source.text)
        self.complete_probe(source.json()["id"])
        route = f"/api/v1/resources/{SCOPE}/docker/containers/{CONTAINER}/restart-drafts"
        self.assertEqual(self.client.post(route, json={}, headers={"Origin": self.headers()["Origin"]}).status_code, 403)
        response = self.client.post(route, json={"confirm_stateless_test": True}, headers=self.headers())
        self.assertEqual(response.status_code, 201, response.text)
        return response

    def test_fresh_schema_supports_whole_plan_through_approval_with_execution_blocked(self):
        draft = self.draft()
        route = draft.headers["location"]
        headers = self.headers(**{"If-Match": draft.headers["etag"], "Idempotency-Key": REQUEST_KEY})
        read = self.client.get(route)
        self.assertEqual(read.json(), draft.json())
        self.assertEqual(read.headers["etag"], draft.headers["etag"])

        self.now += 1
        preflight = self.client.post(route + "/preflight", json={}, headers=headers)
        self.assertEqual(preflight.status_code, 202, preflight.text)
        retry = self.client.post(route + "/preflight", json={}, headers=headers)
        self.assertEqual(retry.json(), preflight.json())
        job = preflight.json()["id"]
        self.complete_probe(job)
        evidence = {"probe_id": job, "request_key": REQUEST_KEY}
        decision = self.client.post(route + "/backup-decision", json=evidence, headers=headers)
        self.assertEqual(decision.status_code, 200, decision.text)
        self.assertEqual(decision.json()["backup_gate"], "BACKUP_NOT_REQUIRED")

        grant = self.client.post("/api/v1/auth/reauth", headers=self.headers(),
                                 json={"password": PASSWORD, "plan_hash": draft.json()["plan_hash"]})
        self.assertEqual(grant.status_code, 200, grant.text)
        content = {**evidence, "reauth_id": grant.json()["id"]}
        approved = self.client.post(route + "/approval", json=content, headers=headers)
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["approval"], "REHEARSAL_RECORDED")
        self.assertEqual(approved.json()["execution"], "BLOCKED")
        replay = self.client.post(route + "/approval", json=content, headers=headers)
        self.assertEqual(replay.json()["code"], "CHANGE_PLAN_ALREADY_APPROVED")
        revised = self.client.put(route, json={}, headers=headers)
        self.assertEqual(revised.status_code, 200, revised.text)
        self.assertEqual(revised.json()["revision"], 2)
        stale = self.client.post(route + "/approval", json=content, headers=headers)
        self.assertEqual(stale.json()["code"], "STALE_REVISION")
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT DISTINCT action FROM jobs").fetchall()[0][0], "host.probe")
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 2)

    def test_scoped_session_cannot_read_another_vps_draft(self):
        draft = self.draft()
        self.create_user(name="limited", grants=[{"permission": "vps:read", "resource_id": identifier()}])
        other = self.other_client("limited")
        self.assertEqual(other.get(draft.headers["location"]).status_code, 404)
