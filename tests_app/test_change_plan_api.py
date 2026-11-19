from unittest.mock import Mock

import asyncssh

from hostorbit.errors import Denied
from hostorbit.restart_requests import RestartWorker
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.broker import Broker
from hostorbit.runtime.ipc import Peer
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from tests_runtime.fixtures import ACTOR, BROKER_UID, SECRET, TARGET, WORKER_UID, policy, private_key, trusted_time
from hostorbit.database import identifier
from hostorbit.queue import JobQueue
from test_auth_api import Fixture, PASSWORD, SCOPE


CONTAINER = "c" * 64
REQUEST_KEY = "fixture-preflight-001"
STARTED_AT = "2026-11-18T01:02:03.123456789Z"


class ChangePlanAPITests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=self.auth.clock)
        self.queue.register_resource(SCOPE, "a" * 64, 1)

    def complete_probe(self, job, *, started_at=STARTED_AT):
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
                "dependency_status": "ISOLATED", "published_ports": [], "started_at": started_at,
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
        self.assertEqual(approved.json()["started_at"], STARTED_AT)
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

    def test_approved_restart_runs_through_authority_broker_and_timeline_once(self):
        restart_secret = identifier()
        p = Policy([{**policy().targets[TARGET].value, "id": SCOPE,
                     "capabilities": ["host.probe", "docker.restart"], "restart_secret_ref": restart_secret + ":v1"}])
        with self.store.write() as db:
            db.execute("UPDATE resources SET scope_digest=? WHERE id=?", (p.targets[SCOPE].scope_digest, SCOPE))
        directory = self.store.path.parent
        gate = Authority.initialize(directory / "gate", p, clock=lambda: self.now,
                                    time_health=trusted_time(directory / "time", lambda: self.now))
        self.addCleanup(gate.close)
        credential = directory / "restart-key"
        new_private_file(credential, b"x" * 32)
        vault = Vault.initialize(directory / "vault", credential)
        vault.import_ssh(SECRET, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=SCOPE)
        vault.import_restart_ssh(restart_secret, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=SCOPE)
        replacement = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
        restart_ref = restart_secret + ":v1"
        vault.change_key(restart_ref, anchor=restart_ref, scope_digest=p.targets[SCOPE].scope_digest,
                         purpose="docker.restart", target=SCOPE, consumer_uid=WORKER_UID, policy_revision=1, key=replacement)
        with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
            vault.use_restart_ssh(SECRET + ":v1", worker_uid=WORKER_UID, target=SCOPE, policy_revision=1)
        Broker.initialize(directory / "broker", p)
        broker_gate = Mock(call=lambda name, args: gate.dispatch("broker", Peer(1, BROKER_UID, BROKER_UID), name, args))
        execute = Mock(return_value={"outcome": "SUCCEEDED", "code": "DOCKER_RESTART_VERIFIED"})
        broker = Broker(directory / "broker", p, vault, broker_gate, bytes(gate.key.verify_key), worker_uid=WORKER_UID,
                        clock=lambda: self.now, execute_restart=execute)
        worker_peer = Peer(1, WORKER_UID, WORKER_UID)
        worker = RestartWorker(self.store,
                               Mock(call=lambda name, args: gate.dispatch("worker", worker_peer, name, args)),
                               Mock(call=lambda name, args: broker.dispatch("worker", worker_peer, name, args)),
                               lambda: self.now, {SCOPE: restart_secret + ":v1"})

        def queue_restart():
            draft = self.draft()
            route = draft.headers["location"]
            headers = self.headers(**{"If-Match": draft.headers["etag"], "Idempotency-Key": REQUEST_KEY})
            self.now += 1
            preflight = self.client.post(route + "/preflight", json={}, headers=headers)
            self.assertEqual(preflight.status_code, 202, preflight.text)
            job = preflight.json()["id"]
            self.complete_probe(job)
            evidence = {"probe_id": job, "request_key": REQUEST_KEY}
            response = self.client.post(route + "/backup-decision", json=evidence, headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            grant = self.client.post("/api/v1/auth/reauth", headers=self.headers(),
                                     json={"password": PASSWORD, "plan_hash": draft.json()["plan_hash"]})
            approval = self.client.post(route + "/approval", json={**evidence, "reauth_id": grant.json()["id"]}, headers=headers)
            self.assertEqual(approval.status_code, 200, approval.text)
            body = {**evidence, "approval_id": approval.json()["approval_id"]}
            planned = self.client.post(route + "/execution-requests", json=body, headers=headers)
            self.assertEqual(planned.status_code, 202, planned.text)
            duplicate = self.client.post(route + "/execution-requests", json=body, headers=headers)
            self.assertEqual(duplicate.json(), planned.json())
            return planned

        def states(request):
            response = self.client.get(request.headers["location"])
            self.assertEqual(response.status_code, 200, response.text)
            return [item["status"] for item in response.json()["items"]]

        request = queue_restart()
        self.assertEqual(states(request), ["QUEUED"])
        self.assertTrue(worker.run_one())
        self.assertFalse(worker.run_one())
        self.assertEqual(states(request), ["QUEUED", "INTENT_PREPARED", "DISPATCHING", "SUCCEEDED"])
        plan_id = request.headers["location"].split("/")[-2]
        detail = self.client.get(f"/api/v1/audit/change-plans/{plan_id}/revisions/1")
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["operation"], {
            "id": request.json()["id"], "status": "SUCCEEDED", "reason": "DOCKER_RESTART_VERIFIED"})
        self.assertEqual(detail.json()["backup_decision"]["gate"], "BACKUP_NOT_REQUIRED")
        self.assertEqual(execute.call_args.args[1], replacement)
        self.assertEqual(execute.call_args.args[3]["started_at"], STARTED_AT)
        execute.assert_called_once()

        def reconcile(request, attempt=1, client=None, headers=None):
            path = request.headers["location"].removesuffix("/execution-timeline")
            path += f"/execution-requests/{request.json()['id']}/reconciliations/{attempt}"
            return (client or self.client).post(path, json={}, headers=headers if headers is not None else self.headers())

        normal_call = worker.broker.call

        def lose_reply(name, args):
            value = normal_call(name, args)
            if name == "use_for_scoped_ssh":
                raise Denied("RPC_UNAVAILABLE")
            return value

        worker.broker.call = lose_reply
        for saved, expected in (({"outcome": "SUCCEEDED", "code": "DOCKER_RESTART_VERIFIED"}, "RECONCILED_SUCCEEDED"),
                                ({"outcome": "DENIED", "code": "STALE_BASELINE"}, "RECONCILED_FAILED")):
            execute.return_value = saved
            confirmed = queue_restart()
            self.assertTrue(worker.run_one())
            self.assertEqual(states(confirmed)[-1], "UNKNOWN_OUTCOME")
            forbidden = reconcile(confirmed, headers={"Origin": self.headers()["Origin"]})
            self.assertEqual(forbidden.status_code, 403)
            first = reconcile(confirmed)
            self.assertEqual(first.status_code, 202, first.text)
            self.assertEqual(reconcile(confirmed).json(), first.json())
            self.assertEqual(reconcile(confirmed, 2).status_code, 409)
            before = execute.call_count
            self.assertTrue(worker.run_one())
            self.assertFalse(worker.run_one())
            self.assertEqual(states(confirmed)[-3:], ["UNKNOWN_OUTCOME", "RECONCILIATION_REQUESTED", expected])
            self.assertEqual(reconcile(confirmed).json()["status"], expected)
            self.assertEqual(reconcile(confirmed, 2).status_code, 409)
            self.assertEqual(execute.call_count, before)

        worker.broker.call = normal_call
        self.now += 900  # Start the next scenario after the Owner reauthentication limit window.
        execute.side_effect = Denied("SSH_RESTART_UNCONFIRMED")
        lost = queue_restart()
        self.assertTrue(worker.run_one())
        worker.recover()
        self.assertFalse(worker.run_one())
        self.assertEqual(states(lost)[-1], "UNKNOWN_OUTCOME")
        for number in (1, 2, 3):
            self.assertEqual(reconcile(lost, number).status_code, 202)
            self.assertTrue(worker.run_one())
            self.assertEqual(states(lost)[-1], "QUARANTINED")
        self.assertEqual(reconcile(lost, 4).status_code, 409)
        blocked = queue_restart()
        self.assertTrue(worker.run_one())
        self.assertEqual(states(blocked), ["QUEUED", "CANCELLED_SAFE"])
        self.assertEqual(execute.call_count, 4)
        self.store.verify_audit()

    def test_preflight_rejects_a_restart_after_saving_the_draft(self):
        draft = self.draft()
        self.assertEqual(draft.json()["baseline"]["started_at"], STARTED_AT)
        headers = self.headers(**{"If-Match": draft.headers["etag"], "Idempotency-Key": REQUEST_KEY})
        self.now += 1
        route = draft.headers["location"]
        preflight = self.client.post(route + "/preflight", json={}, headers=headers)
        self.assertEqual(preflight.status_code, 202, preflight.text)
        job = preflight.json()["id"]
        self.complete_probe(job, started_at="2026-11-18T01:02:04Z")
        decision = self.client.post(route + "/backup-decision", headers=headers,
                                    json={"probe_id": job, "request_key": REQUEST_KEY})
        self.assertEqual(decision.status_code, 409, decision.text)
        self.assertEqual(decision.json()["code"], "STALE_BASELINE")

    def test_scoped_session_cannot_read_another_vps_draft(self):
        draft = self.draft()
        self.create_user(name="limited", grants=[{"permission": "vps:read", "resource_id": identifier()}])
        other = self.other_client("limited")
        self.assertEqual(other.get(draft.headers["location"]).status_code, 404)

    def test_audit_reads_the_exact_revision_and_ignores_unrelated_evidence(self):
        draft = self.draft()
        plan = draft.json()
        route = f"/api/v1/audit/change-plans/{plan['id']}/revisions/"
        self.now += 1
        headers = self.headers(**{"If-Match": draft.headers["etag"], "Idempotency-Key": REQUEST_KEY})
        job = self.client.post(draft.headers["location"] + "/preflight", json={}, headers=headers).json()["id"]
        self.complete_probe(job)
        decision = self.client.post(draft.headers["location"] + "/backup-decision",
                                    json={"probe_id": job, "request_key": REQUEST_KEY}, headers=headers)
        self.assertEqual(decision.status_code, 200, decision.text)
        newer = self.client.put(draft.headers["location"], json={}, headers=headers)
        self.assertEqual(newer.status_code, 200, newer.text)
        with self.store.write() as db:
            self.store.event(db, at=self.now, actor=self.owner, kind="change_plan.backup_evaluated",
                             target=SCOPE, correlation=plan["id"], outcome="DENIED", details={
                                 "revision": 1, "plan_hash": newer.json()["plan_hash"],
                                 "backup_gate": "BACKUP_GATE_DENIED", "backup_gate_reason": "UNRELATED"})
            self.store.event(db, at=self.now, actor=self.owner, kind="change_plan.restart_finished",
                             target=SCOPE, correlation=plan["id"], outcome="SUCCEEDED",
                             details={"operation_id": identifier(), "revision": 1})
        saved = self.client.get(route + "1")
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(saved.json(), {"plan": plan, "operation": None, "backup_decision": {
            "gate": "BACKUP_NOT_REQUIRED", "reason": "RESTART_STATELESS_TEST_CONTAINER"}})
        self.assertEqual(self.client.get(route + "2").json(), {
            "plan": newer.json(), "operation": None, "backup_decision": None})
        self.assertNotIn("probe_nonce", saved.text)
        self.assertNotIn("scope_digest", saved.text)
        self.assertEqual(self.client.get(route + "3").status_code, 404)
        with self.store.write() as db:
            db.execute("UPDATE change_plan_drafts SET plan_hash=? WHERE id=? AND revision=1", ("0"*64, plan["id"]))
        self.assertEqual(self.client.get(route + "1").json()["code"], "CHANGE_PLAN_INTEGRITY")

    def test_audit_plan_requires_both_audit_and_current_resource_access(self):
        plan = self.draft().json()
        route = f"/api/v1/audit/change-plans/{plan['id']}/revisions/1"
        self.create_user(name="scoped", role="Auditor", grants=[
            {"permission": "audit:read", "resource_id": "*"}, {"permission": "vps:read", "resource_id": SCOPE}])
        other = self.other_client("scoped")
        self.assertEqual(other.get(route).status_code, 200)
        with self.store.write() as db:
            db.execute("DELETE FROM grants WHERE permission='vps:read'")
        response = other.get(route)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(CONTAINER, response.text)
        self.create_user(name="only-vps", grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        response = self.other_client("only-vps").get(route)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(CONTAINER, response.text)
