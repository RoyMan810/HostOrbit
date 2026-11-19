import asyncssh
from fastapi.testclient import TestClient

from hostorbit.api import create_app
from hostorbit.config import Settings
from hostorbit.database import identifier
from hostorbit.runtime.policy import Policy
from test_auth_api import Fixture, ORIGIN, OTHER, SCOPE


class EnrollmentTests(Fixture):
    def setUp(self):
        super().setUp()
        self.pins, targets = {}, []
        for i, identity in enumerate((SCOPE, OTHER), start=1):
            key = asyncssh.generate_private_key("ssh-ed25519")
            self.pins[identity] = key.get_fingerprint("sha256")
            targets.append({"id": identity, "ip": f"192.0.2.{i}", "port": 22, "allowed_cidrs": ["192.0.2.0/24"],
                            "host_key": key.export_public_key().decode().strip(), "secret_ref": identifier() + ":v1",
                            "policy_revision": i, "dependencies": [], "capabilities": ["host.probe"]})
        self.catalog = Policy(targets).enrollment_catalog()
        self.assertEqual(set(self.catalog[SCOPE]), {"fingerprint", "scope_digest", "policy_revision"})
        self.client = self.enterContext(TestClient(create_app(Settings(self.store.path, ORIGIN), auth=self.auth,
                                                               enrollment_catalog=self.catalog), base_url=ORIGIN))
        self.csrf = self.login()

    def enroll(self, identity, pin, *, headers=None, client=None):
        return (client or self.client).post("/api/v1/resources", json={"resource_id": identity, "fingerprint": pin},
                                            headers=self.headers() if headers is None else headers)

    def test_independent_pin_and_target_required_and_mismatch_audited(self):
        self.assertEqual(self.enroll(SCOPE, self.pins[OTHER]).status_code, 412)
        self.assertEqual(self.enroll(identifier(), self.pins[SCOPE]).status_code, 404)
        self.assertEqual(self.enroll(SCOPE, "untrusted").status_code, 422)
        self.assertEqual(self.enroll(SCOPE, self.pins[SCOPE], headers={"Origin": ORIGIN}).status_code, 403)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM resources").fetchone()[0], 0)
            record = db.execute("SELECT * FROM audit WHERE event='resource.fingerprint_mismatch'").fetchone()
            self.assertEqual((record["target_id"], record["actor_id"], record["outcome"]), (SCOPE, self.owner, "DENIED"))
        response = self.enroll(SCOPE, self.pins[SCOPE])
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.client.get(response.headers["location"]).json()["observation"]["status"], "NOT_CHECKED")
        self.assertEqual(self.enroll(SCOPE, self.pins[SCOPE]).status_code, 409)
        with self.store.read() as db:
            row = db.execute("SELECT * FROM resources").fetchone()
            self.assertEqual(row["scope_digest"], self.catalog[SCOPE]["scope_digest"])
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def test_only_owner_enrolls_and_operator_probe_stays_scoped(self):
        self.create_user(grants=[{"permission": permission, "resource_id": SCOPE} for permission in ("vps:read", "vps:probe")])
        client = self.enterContext(TestClient(self.client.app, base_url=ORIGIN))
        headers = {"Origin": ORIGIN, "X-CSRF-Token": self.login(client=client, user="operator")}
        self.assertEqual(self.enroll(SCOPE, self.pins[SCOPE], client=client, headers=headers).status_code, 403)
        for target in (SCOPE, OTHER):
            self.assertEqual(self.enroll(target, self.pins[target]).status_code, 201)
        self.assertEqual([v["id"] for v in client.get("/api/v1/resources").json()["items"]], [SCOPE])
        for target, status in ((SCOPE, 202), (OTHER, 403)):
            reply = client.post(f"/api/v1/resources/{target}/observations", json={},
                                headers={**headers, "Idempotency-Key": identifier()})
            self.assertEqual(reply.status_code, status, reply.text)
