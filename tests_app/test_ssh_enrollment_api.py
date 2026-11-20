import asyncio
import unittest
from unittest.mock import patch

import asyncssh
from fastapi.testclient import TestClient

from vpn_orbit.api import create_app
from vpn_orbit.config import Settings
from vpn_orbit.database import identifier
from vpn_orbit.runtime.policy import Policy
from test_auth_api import Fixture, ORIGIN, OTHER, SCOPE


PASSWORD = "ssh-enrollment-password-canary"
IP, OTHER_IP = "192.0.2.8", "192.0.2.9"


class SSHEnrollmentTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        host = asyncssh.generate_private_key("ssh-ed25519")
        different_host = asyncssh.generate_private_key("ssh-ed25519")
        client = asyncssh.generate_private_key("ssh-ed25519")
        self.private_key = client.export_private_key().decode()
        self.host_pin = host.get_fingerprint()
        self.other_pin = different_host.get_fingerprint()
        self.dials, self.auth_methods, self.sessions = [], [], []
        fixture = self

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return username != "anonymous"

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                fixture.auth_methods.append("password")
                return username == "ubuntu" and password == PASSWORD

            def public_key_auth_supported(self):
                return True

            def validate_public_key(self, username, key):
                fixture.auth_methods.append("publickey")
                return username == "ubuntu" and key.public_data == client.public_data

            def session_requested(self):
                fixture.sessions.append(True)
                return False

        server = await asyncssh.listen("127.0.0.1", 0, server_factory=Server, server_host_keys=[host])
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        self.port = server.get_port()
        targets = [{"id": identity, "ip": ip, "port": self.port, "allowed_cidrs": [ip + "/32"],
                    "host_key": key.export_public_key().decode().strip(), "secret_ref": identifier() + ":v1",
                    "policy_revision": 1, "dependencies": [], "capabilities": ["host.probe"]}
                   for identity, ip, key in ((SCOPE, IP, host), (OTHER, OTHER_IP, different_host))]
        catalog = Policy(targets).enrollment_catalog(ssh_endpoints=True)
        self.client = self.enterContext(TestClient(create_app(Settings(self.store.path, ORIGIN), auth=self.auth,
                                                               enrollment_catalog=catalog), base_url=ORIGIN))
        self.csrf = self.login()

        connect = asyncssh.connect

        def loopback_connect(host, *, port, **options):
            # Keep all test traffic local while asserting the address selected by production policy.
            self.dials.append((host, port))
            self.assertIn(host, (IP, OTHER_IP))
            self.assertEqual(port, self.port)
            return connect("127.0.0.1", port=port, **options)

        self.enterContext(patch("vpn_orbit.runtime.ssh_enrollment.asyncssh.connect", loopback_connect))

    async def enroll(self, *, client=None, headers=None, **values):
        body = {"ip": IP, "port": self.port, "username": "ubuntu", "fingerprint": self.host_pin, **values}
        return await asyncio.to_thread((client or self.client).post, "/api/v1/enrollment/ssh",
                                       json=body, headers=self.headers() if headers is None else headers)

    async def test_password_login_failures_and_retry_never_open_a_session(self):
        mismatch = await self.enroll(fingerprint=self.other_pin, password=PASSWORD)
        self.assertEqual(mismatch.status_code, 412)
        blocked = await self.enroll(ip="192.0.2.99", password=PASSWORD)
        self.assertEqual(blocked.status_code, 404)
        self.assertEqual(self.dials, [])

        # A correct console fingerprint does not authorize a different key presented by SSH.
        replaced_host = await self.enroll(ip=OTHER_IP, fingerprint=self.other_pin, password=PASSWORD)
        self.assertEqual(replaced_host.status_code, 412)
        self.assertEqual(self.auth_methods, [])

        wrong_password = await self.enroll(password="wrong-" + PASSWORD)
        no_auth = await self.enroll(username="anonymous", password=PASSWORD)
        self.assertEqual(wrong_password.status_code, 424)
        self.assertEqual(no_auth.status_code, 424)
        self.assertEqual(self.auth_methods, ["password"])
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

        success = await self.enroll(password=PASSWORD)
        self.assertEqual(success.status_code, 201, success.text)
        repeat = await self.enroll(password=PASSWORD)
        self.assertEqual(repeat.status_code, 409)
        self.assertEqual(self.auth_methods, ["password", "password"])
        self.assertEqual(self.dials, [(OTHER_IP, self.port)] + [(IP, self.port)] * 3)
        self.assertEqual(self.sessions, [])
        self.assertEqual(self.client.get(success.headers["location"]).json()["id"], SCOPE)

        for response in (mismatch, blocked, replaced_host, wrong_password, no_auth, success, repeat):
            self.assertNotIn(PASSWORD, response.text)
        self.assertNotIn(PASSWORD, str(self.store.events_after(0)))

    async def test_private_key_and_owner_boundary(self):
        self.create_user(grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        other = self.enterContext(TestClient(self.client.app, base_url=ORIGIN))
        headers = {"Origin": ORIGIN, "X-CSRF-Token": self.login(client=other, user="operator")}
        forbidden = await self.enroll(client=other, headers=headers, private_key=self.private_key)
        csrf_missing = await self.enroll(headers={"Origin": ORIGIN}, private_key=self.private_key)
        ambiguous = await self.enroll(password=PASSWORD, private_key=self.private_key)
        malformed = await self.enroll(private_key="invalid-ssh-key-canary")
        self.assertEqual([reply.status_code for reply in (forbidden, csrf_missing, ambiguous, malformed)], [403, 403, 422, 422])
        self.assertEqual(self.dials, [])

        success = await self.enroll(private_key=self.private_key)
        self.assertEqual(success.status_code, 201, success.text)
        self.assertEqual(set(self.auth_methods), {"publickey"})
        self.assertEqual(self.sessions, [])
        self.assertNotIn("invalid-ssh-key-canary", malformed.text)
        self.assertNotIn("PRIVATE KEY", success.text)
        self.assertNotIn("PRIVATE KEY", str(self.store.events_after(0)))
