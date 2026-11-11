from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from hostorbit.auth import COOKIE
from hostorbit.errors import Denied
from test_auth_api import Fixture, OTHER, PASSWORD, SCOPE


class PermissionTests(Fixture):
    def test_audit_integrity_is_restricted_to_global_audit_read(self):
        endpoint = "/api/v1/audit/integrity"
        self.create_user()
        operator = self.other_client("operator")
        with patch.object(self.store, "verify_audit", wraps=self.store.verify_audit) as verify:
            self.assertEqual(operator.get(endpoint).status_code, 403)
            verify.assert_not_called()
        self.create_user(name="auditor", role="Auditor", grants=[{"permission": "audit:read", "resource_id": "*"}])
        auditor = self.other_client("auditor")
        result = auditor.get(endpoint)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {"status": "verified"})
        self.assertEqual(result.headers["Cache-Control"], "no-store")

    def test_audit_integrity_distinguishes_corruption_from_unavailable_storage(self):
        endpoint = "/api/v1/audit/integrity"
        with patch.object(self.store, "verify_audit", side_effect=OSError("private-canary")):
            unavailable = self.client.get(endpoint)
        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(unavailable.json()["code"], "STORAGE_UNAVAILABLE")
        self.assertNotIn("private-canary", unavailable.text)
        with self.store.write() as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit SET details='private-canary' WHERE seq=1")
        corrupt = self.client.get(endpoint)
        self.assertEqual(corrupt.status_code, 200)
        self.assertEqual(corrupt.json(), {"status": "invalid"})

    def test_operator_scope_and_auditor_read_only_permissions_are_checked_in_manager(self):
        self.create_user(grants=[{"permission": "vps:restart", "resource_id": SCOPE}])
        operator = self.other_client("operator")
        token = operator.cookies.get(COOKIE)
        self.auth.require_permission(token, "vps:restart", SCOPE)
        for permission, target in (("vps:restart", OTHER), ("users:manage", "*"), ("secrets:Manage", SCOPE), ("View Secret", SCOPE)):
            with self.subTest(permission=permission), self.assertRaises(Denied):
                self.auth.require_permission(token, permission, target)
        result = operator.get("/api/v1/users/" + self.owner)
        self.assertEqual(result.status_code, 403)
        self.create_user(name="auditor", role="Auditor", grants=[{"permission": "audit:read", "resource_id": "*"}])
        auditor = self.other_client("auditor")
        self.assertEqual(auditor.get("/api/v1/audit").status_code, 200)
        self.assertEqual(auditor.get("/api/v1/openapi.json").status_code, 403)
        with self.assertRaises(Denied):
            self.auth.require_permission(auditor.cookies.get(COOKIE), "vps:restart", SCOPE)

    def test_no_operator_wildcard_or_view_secret_grant_and_owner_is_local_only(self):
        current = self.client.get("/api/v1/users").headers["etag"]
        base = {"username": "operator", "password": PASSWORD, "role": "Operator"}
        for grants in ([{"permission": "vps:restart", "resource_id": "*"}], [{"permission": "View Secret", "resource_id": SCOPE}]):
            result = self.client.post("/api/v1/users", headers=self.headers(**{"If-Match": current}), json={**base, "grants": grants})
            self.assertEqual(result.status_code, 422)
        result = self.client.post("/api/v1/users", headers=self.headers(**{"If-Match": current}), json={**base, "role": "Owner"})
        self.assertEqual(result.status_code, 422)

    def test_admin_cannot_delegate_beyond_own_scope_or_modify_owner_or_admin(self):
        self.create_user(name="admin", role="Admin", grants=[
            {"permission": "users:manage", "resource_id": "*"},
            {"permission": "vps:restart", "resource_id": SCOPE},
        ])
        admin = self.other_client("admin")
        csrf = admin.get("/api/v1/auth/session").json()["csrf_token"]
        def create(resource, role="Operator"):
            version = admin.get("/api/v1/users").headers["etag"]
            return admin.post("/api/v1/users", headers={"Origin": "https://hostorbit.test", "X-CSRF-Token": csrf, "If-Match": version},
                              json={"username": "delegated", "password": PASSWORD, "role": role,
                                    "grants": [{"permission": "vps:restart", "resource_id": resource}]})
        self.assertEqual(create(OTHER).status_code, 403)
        self.assertEqual(create(SCOPE, "Admin").status_code, 403)
        self.assertEqual(create(SCOPE).status_code, 201)
        self.assertEqual(admin.get("/api/v1/users/" + self.owner).status_code, 404)
        names = [u["username"] for u in admin.get("/api/v1/users").json()["items"]]
        self.assertNotIn("roman", names)
        self.assertNotIn("admin", names)

    def test_role_change_or_disable_revokes_all_sessions_and_invalidates_csrf(self):
        user = self.create_user(grants=[{"permission": "vps:restart", "resource_id": SCOPE}])
        first = self.other_client("operator")
        second = self.other_client("operator")
        version = self.client.get("/api/v1/users/" + user["id"]).headers["etag"]
        result = self.client.put("/api/v1/users/" + user["id"], headers=self.headers(**{"If-Match": version}),
                                 json={"role": "Auditor", "grants": [], "disabled": True})
        self.assertEqual(result.status_code, 200)
        for client in (first, second):
            self.assertEqual(client.get("/api/v1/auth/session").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/auth/session").status_code, 200)

    def test_etag_is_required_and_stale_concurrent_updates_have_one_winner(self):
        user = self.create_user()
        token = self.client.cookies.get(COOKIE)
        endpoint = "/api/v1/users/" + user["id"]
        version = self.client.get(endpoint).headers["etag"]
        result = self.client.put(endpoint, headers=self.headers(), json={"role": "Auditor"})
        self.assertEqual(result.status_code, 428)
        def update(role):
            try:
                self.auth.update_user(token, self.csrf, user["id"], role, [], False,
                                      if_match=version, correlation="concurrent-fixture")
                return 200
            except Denied as error:
                return error.status
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(update, ("Auditor", "Operator")), [200, 412])
        current = self.client.get(endpoint)
        self.assertEqual(current.json()["revision"], 2)
        self.assertNotEqual(current.headers["etag"], version)

    def test_stale_collection_does_not_create_a_second_user(self):
        version = self.client.get("/api/v1/users").headers["etag"]
        body = {"username": "operator", "password": PASSWORD, "role": "Operator"}
        self.assertEqual(self.client.post("/api/v1/users", json=body, headers=self.headers()).status_code, 428)
        self.assertEqual(self.client.post("/api/v1/users", json=body, headers=self.headers(**{"If-Match": version})).status_code, 201)
        body["username"] = "second"
        self.assertEqual(self.client.post("/api/v1/users", json=body, headers=self.headers(**{"If-Match": version})).status_code, 412)
