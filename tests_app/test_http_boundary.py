import json

from fastapi.testclient import TestClient

from hostorbit.api import create_app
from hostorbit.auth import COOKIE
from hostorbit.config import Settings
from test_auth_api import Fixture, ORIGIN, PASSWORD


class HttpBoundaryTests(Fixture):
    def test_http_spoofed_proto_cross_origin_form_and_large_body_are_denied(self):
        body = {"username": "roman", "password": PASSWORD}
        with TestClient(self.client.app, base_url="http://hostorbit.test") as client:
            result = client.post("/api/v1/auth/login", json=body, headers={"Origin": ORIGIN, "X-Forwarded-Proto": "https"})
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.json()["code"], "HTTPS_REQUIRED")
        result = self.client.post("/api/v1/auth/login", json=body, headers={"Origin": "https://attacker.test"})
        self.assertEqual(result.status_code, 403)
        result = self.client.post("/api/v1/auth/login", data=body, headers={"Origin": ORIGIN})
        self.assertEqual(result.status_code, 415)
        result = self.client.post("/api/v1/auth/login", content=(b"x" * 9000 for _ in range(2)), headers={"Origin": ORIGIN, "Content-Type": "application/json"})
        self.assertEqual(result.status_code, 413)
        result = self.client.post("/api/v1/auth/login", json=body, headers={"Origin": ORIGIN, "Content-Length": "9" * 5000})
        self.assertEqual(result.status_code, 413)

    def test_only_explicit_proxy_can_supply_scheme_and_single_client_ip(self):
        settings = Settings(self.store.path, ORIGIN, ("192.0.2.0/24",))
        with TestClient(create_app(settings, auth=self.auth), base_url="http://hostorbit.test", client=("192.0.2.1", 1234)) as client:
            headers = {"Origin": ORIGIN, "X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.5"}
            body = {"username": "roman", "password": PASSWORD}
            self.assertEqual(client.post("/api/v1/auth/login", json=body, headers=headers).status_code, 200)
            with self.store.connect() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM login_attempts WHERE ip='198.51.100.5'").fetchone()[0], 1)
            headers["X-Forwarded-For"] = "198.51.100.5, 198.51.100.6"
            self.assertEqual(client.post("/api/v1/auth/login", json=body, headers=headers).status_code, 400)

    def test_validation_and_error_envelopes_never_echo_secret_input(self):
        canary = "CANARY-credential-must-not-be-reflected"
        for body in ({"username": "roman", "password": {"secret": canary}}, {"username": "roman", "password": "x", canary: True}):
            result = self.client.post("/api/v1/auth/login", json=body, headers={"Origin": ORIGIN})
            self.assertEqual(result.status_code, 422)
            self.assertNotIn(canary, result.text)
            self.assertEqual(set(result.json()), {"code", "message", "correlation_id", "details"})
            self.assertEqual(result.headers["cache-control"], "no-store")
        for path in ("/api/v1/no-such-route", "/openapi.json", "/docs"):
            result = self.client.get(path)
            self.assertEqual(result.status_code, 404)
            self.assertEqual(set(result.json()), {"code", "message", "correlation_id", "details"})

    def test_private_schema_and_sse_replay_expose_only_persisted_outbox(self):
        with TestClient(self.client.app, base_url=ORIGIN) as anonymous:
            self.assertEqual(anonymous.get("/api/v1/openapi.json").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/openapi.json").status_code, 200)
        events = self.client.get("/api/v1/events")
        self.assertEqual(events.status_code, 200)
        values = [json.loads(line[6:]) for line in events.text.splitlines() if line.startswith("data: ")]
        self.assertEqual(values, [v["event"] for v in self.store.events_after(0)])
        self.assertNotIn(PASSWORD, events.text)
        self.assertNotIn(self.client.cookies.get(COOKIE), events.text)
        cursor = self.store.events_after(0)[-1]["seq"]
        replay = self.client.get("/api/v1/events", headers={"Last-Event-ID": str(cursor)})
        self.assertNotIn("data:", replay.text)
        self.assertEqual(self.client.get("/api/v1/events", headers={"Last-Event-ID": "-1"}).status_code, 400)

    def test_failed_outbox_write_rolls_back_user_creation_and_does_not_emit_success(self):
        before = self.store.events_after(0)
        with self.store.connect() as db:
            db.executescript("CREATE TRIGGER fixture_fail_user_outbox BEFORE INSERT ON outbox WHEN NEW.payload LIKE '%user.created%' BEGIN SELECT RAISE(ABORT,'fixture full'); END;")
        version = self.client.get("/api/v1/users").headers["etag"]
        result = self.client.post("/api/v1/users", headers=self.headers(**{"If-Match": version}),
                                  json={"username": "operator", "password": PASSWORD, "role": "Operator"})
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(PASSWORD, result.text)
        with self.store.connect() as db:
            self.assertIsNone(db.execute("SELECT id FROM users WHERE username='operator'").fetchone())
        self.assertEqual(before, self.store.events_after(0))
        self.store.verify_audit()

    def test_invalid_public_origins_and_oversize_audit_cursor_are_rejected(self):
        for origin in ("http://hostorbit.test", "https://hostorbit.test/", "https://user:secret@hostorbit.test", "https://bad host", "https://hostorbit.test:443"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                Settings(self.store.path, origin)
        self.assertEqual(self.client.get("/api/v1/audit", params={"after": str(2**64)}).status_code, 422)
