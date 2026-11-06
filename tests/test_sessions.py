from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stage0.sessions import Principal, Role, SessionDenied, SessionLab


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_700_000_000
        self.path = Path(self.enterContext(TemporaryDirectory())) / "sessions.sqlite3"
        self.lab = SessionLab.create(
            self.path, {"operator": Role.OPERATOR, "owner": Role.OWNER}, clock=self.clock,
        )
        self.first = self.lab.issue_after_authentication("operator")

    def clock(self):
        return self.now

    def reopen(self):
        return SessionLab(self.path, clock=self.clock)

    def assert_revoked(self, lab, *credentials):
        for tokens in credentials:
            with self.assertRaisesRegex(SessionDenied, "^SESSION_REQUIRED$"):
                lab.authenticate_request(tokens.session_token, mutating=False)

    def test_idle_timeout_is_refreshed_by_valid_requests_and_expires_at_30_minutes(self):
        for _ in range(2):
            self.now += 29 * 60
            self.assertEqual(
                self.lab.authenticate_request(self.first.session_token, mutating=False),
                Principal("operator", Role.OPERATOR),
            )
        self.now += 30 * 60
        self.assert_revoked(self.reopen(), self.first)
        self.now -= 1
        self.assert_revoked(self.reopen(), self.first)

    def test_absolute_timeout_expires_at_12_hours_even_with_activity(self):
        start = self.now
        for minute in range(29, 12 * 60, 29):
            self.now = start + minute * 60
            self.lab.authenticate_request(self.first.session_token, mutating=False)
        self.now = start + 12 * 60 * 60 - 1
        self.lab.authenticate_request(self.first.session_token, mutating=False)
        self.now += 1
        self.assert_revoked(self.lab, self.first)

    def test_mutation_requires_bound_csrf_and_denial_does_not_refresh_idle(self):
        other = self.lab.issue_after_authentication("operator")
        self.assertEqual(
            self.lab.authenticate_request(self.first.session_token, mutating=True, csrf_token=self.first.csrf_token),
            Principal("operator", Role.OPERATOR),
        )
        self.now += 30 * 60 - 1
        for csrf in (None, other.csrf_token, "wrong"):
            with self.assertRaisesRegex(SessionDenied, "^CSRF_REQUIRED$"):
                self.lab.authenticate_request(self.first.session_token, mutating=True, csrf_token=csrf)
        with self.assertRaisesRegex(SessionDenied, "^SESSION_REQUIRED$"):
            self.lab.authenticate_request(None, mutating=True, csrf_token=self.first.csrf_token)
        self.now += 1
        self.assert_revoked(self.lab, self.first)

    def test_logout_requires_csrf_and_revokes_only_the_current_session(self):
        other = self.lab.issue_after_authentication("operator")
        with self.assertRaisesRegex(SessionDenied, "^CSRF_REQUIRED$"):
            self.lab.logout(self.first.session_token, csrf_token=other.csrf_token)
        self.lab.logout(self.first.session_token, csrf_token=self.first.csrf_token)
        opened = self.reopen()
        self.assert_revoked(opened, self.first)
        opened.authenticate_request(other.session_token, mutating=False)

    def test_role_change_revokes_all_affected_sessions_and_persists_new_role(self):
        other = self.lab.issue_after_authentication("operator")
        owner = self.lab.issue_after_authentication("owner")
        self.lab.change_role("operator", Role.AUDITOR)
        opened = self.reopen()
        self.assert_revoked(opened, self.first, other)
        self.assertEqual(opened.authenticate_request(owner.session_token, mutating=False).role, Role.OWNER)
        fresh = opened.issue_after_authentication("operator")
        self.assertEqual(opened.authenticate_request(fresh.session_token, mutating=False).role, Role.AUDITOR)

    def test_explicit_revocation_is_durable(self):
        other = self.lab.issue_after_authentication("operator")
        owner = self.lab.issue_after_authentication("owner")
        self.lab.revoke_sessions("operator")
        opened = self.reopen()
        self.assert_revoked(opened, self.first, other)
        opened.authenticate_request(owner.session_token, mutating=False)

    def test_authentication_rotates_the_presented_session_and_csrf(self):
        other = self.lab.issue_after_authentication("operator")
        fresh = self.lab.issue_after_authentication("operator", previous_token=self.first.session_token)
        self.assert_revoked(self.lab, self.first)
        with self.assertRaisesRegex(SessionDenied, "^CSRF_REQUIRED$"):
            self.lab.authenticate_request(fresh.session_token, mutating=True, csrf_token=self.first.csrf_token)
        self.lab.authenticate_request(fresh.session_token, mutating=True, csrf_token=fresh.csrf_token)
        self.lab.authenticate_request(other.session_token, mutating=False)
