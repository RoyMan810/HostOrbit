from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from argon2 import PasswordHasher, Type
from fastapi.testclient import TestClient

from hostorbit.api import create_app
from hostorbit.auth import ABSOLUTE_SECONDS, COOKIE, IDLE_SECONDS, AuthService
from hostorbit.cli import main
from hostorbit.config import Settings
from hostorbit.database import Store
from hostorbit.errors import Denied


ORIGIN = "https://hostorbit.test"
PASSWORD = "Canary-password-for-tests-117!"
SCOPE = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
OTHER = "01JCYQZ4T9V8MNVYEH3D2M7Q1B"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store.initialize(self.directory / "controller.sqlite3")
        self.now = 1_800_000_000
        self.auth = AuthService(self.store, clock=lambda: self.now)
        self.owner = self.auth.create_owner(self.auth.issue_bootstrap(), "roman", PASSWORD)
        self.client = self.enterContext(TestClient(create_app(Settings(self.store.path, ORIGIN), auth=self.auth), base_url=ORIGIN))
        self.csrf = self.login()

    def login(self, *, client=None, user="roman", secret=PASSWORD):
        client = client or self.client
        result = client.post("/api/v1/auth/login", json={"username": user, "password": secret}, headers={"Origin": ORIGIN})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()["csrf_token"]

    def headers(self, **more):
        return {"Origin": ORIGIN, "X-CSRF-Token": self.csrf, **more}

    def create_user(self, *, name="operator", role="Operator", grants=None):
        current = self.client.get("/api/v1/users").headers["etag"]
        result = self.client.post("/api/v1/users", headers=self.headers(**{"If-Match": current}),
                                  json={"username": name, "password": PASSWORD, "role": role, "grants": grants or []})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def other_client(self, name):
        client = self.enterContext(TestClient(self.client.app, base_url=ORIGIN))
        self.login(client=client, user=name)
        return client


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store.initialize(self.directory / "controller.sqlite3")
        self.now = 1_800_000_000
        self.auth = AuthService(self.store, clock=lambda: self.now)

    def test_first_web_visitor_cannot_bootstrap_owner_and_token_is_local_single_use(self):
        with TestClient(create_app(Settings(self.store.path, ORIGIN), auth=self.auth), base_url=ORIGIN) as client:
            for route in ("/register-admin", "/api/v1/register-admin", "/api/v1/auth/bootstrap", "/api/v1/owner"):
                result = client.post(route, json={"username": "visitor", "password": PASSWORD}, headers={"Origin": ORIGIN})
                self.assertEqual(result.status_code, 404)
            with self.store.connect() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM users").fetchone()[0], 0)
        token = self.auth.issue_bootstrap()
        self.auth.create_owner(token, "roman", PASSWORD)
        with self.assertRaises(Denied):
            self.auth.create_owner(token, "second", PASSWORD)
        with self.assertRaisesRegex(Denied, "OWNER_ALREADY_EXISTS"):
            self.auth.issue_bootstrap()

    def test_bootstrap_expiry_rotation_and_concurrent_consumption(self):
        old = self.auth.issue_bootstrap()
        token = self.auth.issue_bootstrap()
        with self.assertRaisesRegex(Denied, "BOOTSTRAP_INVALID"):
            self.auth.create_owner(old, "roman", PASSWORD)
        self.now += 600
        with self.assertRaisesRegex(Denied, "BOOTSTRAP_INVALID"):
            self.auth.create_owner(token, "roman", PASSWORD)
        token = self.auth.issue_bootstrap()
        def create(name):
            try:
                self.auth.create_owner(token, name, PASSWORD)
                return "created"
            except Denied:
                return "denied"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(create, ("roman", "second")))
        self.assertCountEqual(outcomes, ["created", "denied"])

    def test_local_cli_creates_owner_without_password_or_token_in_arguments(self):
        # CLI clock uses wall time, so issue this token with its own current clock.
        token = AuthService(self.store).issue_bootstrap()
        import io
        from contextlib import redirect_stdout
        output = io.StringIO()
        with patch("hostorbit.cli.getpass.getpass", side_effect=[token, PASSWORD, PASSWORD]), redirect_stdout(output):
            self.assertEqual(main(["--database", str(self.store.path), "create-owner", "--username", "roman"]), 0)
        self.assertNotIn(token, output.getvalue())
        self.assertNotIn(PASSWORD, output.getvalue())

    def test_new_passwords_require_fourteen_characters_and_api_cli_refuses_root(self):
        token = self.auth.issue_bootstrap()
        with self.assertRaisesRegex(Denied, "PASSWORD_POLICY"):
            self.auth.create_owner(token, "roman", "x" * 13)
        import io
        from contextlib import redirect_stderr
        message = io.StringIO()
        with patch("os.geteuid", return_value=0), redirect_stderr(message):
            result = main(["--database", str(self.store.path), "serve", "--origin", ORIGIN])
        self.assertEqual(result, 1)
        self.assertIn("UNPRIVILEGED_API_USER_REQUIRED", message.getvalue())


class AuthenticationTests(Fixture):
    def test_cookie_security_rotation_csrf_and_plaintext_absence(self):
        old = self.client.cookies.get(COOKIE)
        result = self.client.post("/api/v1/auth/login", json={"username": "roman", "password": PASSWORD}, headers={"Origin": ORIGIN})
        cookie = result.headers["set-cookie"]
        for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertNotEqual(old, self.client.cookies.get(COOKIE))
        self.assertNotIn(self.client.cookies.get(COOKIE), result.text)
        with self.assertRaisesRegex(Denied, "SESSION_REQUIRED"):
            self.auth.authenticate(old, ip="127.0.0.1")
        tokens = [old, self.client.cookies.get(COOKIE), result.json()["csrf_token"], PASSWORD]
        with self.store.connect() as db:
            content = "\n".join(db.iterdump())
        for value in tokens:
            self.assertNotIn(value, content)
        self.assertNotIn("password_hash", self.client.get("/api/v1/users").text)

    def test_logout_requires_current_csrf_and_revokes_the_session(self):
        for headers in ({"Origin": ORIGIN}, self.headers(**{"X-CSRF-Token": "wrong"})):
            result = self.client.post("/api/v1/auth/logout", json={}, headers=headers)
            self.assertEqual(result.status_code, 403)
        result = self.client.post("/api/v1/auth/logout", json={}, headers=self.headers())
        self.assertEqual(result.status_code, 204)
        self.assertEqual(self.client.get("/api/v1/auth/session").status_code, 401)

    def test_session_read_preserves_csrf_across_tabs_and_another_session_cannot_use_it(self):
        self.assertEqual(self.client.get("/api/v1/auth/session").json()["csrf_token"], self.csrf)
        self.assertEqual(self.client.get("/api/v1/auth/session").json()["csrf_token"], self.csrf)
        another = self.other_client("roman")
        result = another.post("/api/v1/auth/logout", json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": self.csrf})
        self.assertEqual(result.status_code, 403)

    def test_idle_and_absolute_expiry_persist_across_reopen_and_clock_rollback(self):
        token = self.client.cookies.get(COOKIE)
        self.now += IDLE_SECONDS
        with self.assertRaisesRegex(Denied, "SESSION_REQUIRED"):
            self.auth.authenticate(token, ip="127.0.0.1")
        self.now -= 1
        with self.assertRaises(Denied):
            AuthService(self.store, clock=lambda: self.now).authenticate(token, ip="127.0.0.1")
        token = self.auth.login("roman", PASSWORD, ip="127.0.0.1", correlation="fixture")[0].session
        issued = self.now
        for _ in range(24):
            self.now += 1799
            self.auth.authenticate(token, ip="127.0.0.1")
        self.now = issued + ABSOLUTE_SECONDS
        with self.assertRaisesRegex(Denied, "SESSION_REQUIRED"):
            self.auth.authenticate(token, ip="127.0.0.1")

    def test_password_profile_is_argon2id_and_rehashes_older_parameters_at_login(self):
        old = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID).hash(PASSWORD)
        with self.store.write() as db:
            db.execute("UPDATE users SET password_hash=?,password_profile=0 WHERE id=?", (old, self.owner))
        self.login()
        with self.store.connect() as db:
            row = db.execute("SELECT password_hash,password_profile FROM users WHERE id=?", (self.owner,)).fetchone()
        self.assertEqual(row["password_profile"], 1)
        self.assertTrue(row["password_hash"].startswith("$argon2id$"))
        self.assertFalse(self.auth.hasher.check_needs_rehash(row["password_hash"]))

    def test_account_ip_login_limit_and_untrusted_forwarding_do_not_allow_bypass(self):
        for i in range(5):
            response = self.client.post("/api/v1/auth/login", headers={"Origin": ORIGIN, "X-Forwarded-For": f"192.0.2.{i+1}"}, json={"username": "roman", "password": "wrong"})
            self.assertEqual(response.status_code, 401)
        result = self.client.post("/api/v1/auth/login", headers={"Origin": ORIGIN, "X-Forwarded-For": "192.0.2.254"}, json={"username": "roman", "password": PASSWORD})
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.headers["retry-after"], "900")
        self.now += 900
        self.login()

    def test_ip_login_limit_counts_successful_requests_and_api_user_limit_is_durable(self):
        # The setUp login already consumed one IP request.
        for _ in range(19):
            self.login()
        response = self.client.post("/api/v1/auth/login", headers={"Origin": ORIGIN}, json={"username": "roman", "password": PASSWORD})
        self.assertEqual(response.status_code, 429)
        for _ in range(120):
            self.auth.authenticate(self.client.cookies.get(COOKIE), ip="api-peer")
        with self.assertRaisesRegex(Denied, "API_RATE_LIMIT"):
            AuthService(self.store, clock=lambda: self.now).authenticate(self.client.cookies.get(COOKIE), ip="api-peer")
        self.now += 60
        self.auth.authenticate(self.client.cookies.get(COOKIE), ip="api-peer")

    def test_reauth_is_bound_to_session_plan_expiry_and_one_consumption(self):
        token = self.client.cookies.get(COOKIE)
        grant = self.auth.reauthenticate(token, self.csrf, PASSWORD, "a" * 64, correlation="fixture")
        with self.store.write() as db:
            with self.assertRaisesRegex(Denied, "REAUTH_REQUIRED"):
                self.auth.consume_reauthentication(db, token, grant["id"], "b" * 64)
            self.auth.consume_reauthentication(db, token, grant["id"], "a" * 64)
        with self.store.write() as db:
            with self.assertRaisesRegex(Denied, "REAUTH_REQUIRED"):
                self.auth.consume_reauthentication(db, token, grant["id"], "a" * 64)
        fresh = self.auth.reauthenticate(token, self.csrf, PASSWORD, "a" * 64, correlation="fixture")
        another = self.auth.login("roman", PASSWORD, ip="other", correlation="fixture")[0]
        with self.store.write() as db:
            with self.assertRaisesRegex(Denied, "REAUTH_REQUIRED"):
                self.auth.consume_reauthentication(db, another.session, fresh["id"], "a" * 64)
        self.now += 300
        with self.store.write() as db:
            with self.assertRaisesRegex(Denied, "REAUTH_REQUIRED"):
                self.auth.consume_reauthentication(db, token, fresh["id"], "a" * 64)

    def test_reauth_attempt_budget_is_persistent_and_audited(self):
        for _ in range(3):
            result = self.client.post("/api/v1/auth/reauth", headers=self.headers(), json={"password": "wrong", "plan_hash": "a" * 64})
            self.assertEqual(result.status_code, 401)
        result = self.client.post("/api/v1/auth/reauth", headers=self.headers(), json={"password": PASSWORD, "plan_hash": "a" * 64})
        self.assertEqual(result.status_code, 429)
        self.assertTrue(any(v["event"]["event"] == "auth.reauth_limited" for v in self.store.events_after(0)))

    def test_invalid_login_bodies_still_consume_the_ip_request_budget(self):
        for _ in range(19):
            result = self.client.post("/api/v1/auth/login", content=b"{", headers={"Origin": ORIGIN, "Content-Type": "application/json"})
            self.assertEqual(result.status_code, 422)
        result = self.client.post("/api/v1/auth/login", json={"username": "roman", "password": PASSWORD}, headers={"Origin": ORIGIN})
        self.assertEqual(result.status_code, 429)

    def test_unauthenticated_requests_have_a_durable_ip_budget(self):
        for _ in range(600):
            with self.assertRaises(Denied) as caught:
                self.auth.authenticate(None, ip="untrusted-peer")
            self.assertEqual(caught.exception.status, 401)
        with self.assertRaises(Denied) as caught:
            AuthService(self.store, clock=lambda: self.now).authenticate(None, ip="untrusted-peer")
        self.assertEqual(caught.exception.status, 429)
