from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import json
import sqlite3

from hostorbit.auth import COOKIE
from hostorbit.change_drafts import get_draft, save_draft
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.migrations import rehearse
from hostorbit.queue import JobQueue
from hostorbit.runtime.protocol import checksum
from test_auth_api import Fixture, OTHER, SCOPE


CONTAINER = "c" * 64


class ChangeDraftTests(Fixture):
    def setUp(self):
        super().setUp()
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        self.queue.register_resource(SCOPE, "a" * 64, 1)
        self.probe_id = self.probe()
        self.token = self.client.cookies[COOKIE]
        self.output = self.directory / "rehearsal"
        rehearse(self.store, self.output, to_schema=3)

    def probe(self, outcome="SUCCEEDED"):
        job = self.queue.enqueue_probe(self.auth, self.client.cookies[COOKIE], self.csrf, SCOPE, identifier())
        claim, row = self.queue.claim(identifier())
        self.queue.advance(claim, "INTENT_PREPARED", permit={"claims": self.queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            self.queue.advance(claim, state)
        result = {"status": "REACHABLE", "source": "restricted_helper", "observed_at": self.now,
                  "boot_id": "11111111-1111-1111-1111-111111111111",
                  "software": {"docker": "PRESENT", "nginx": "UNKNOWN"},
                  "docker": {"status": "OBSERVED", "containers": [
                      {"id": CONTAINER, "project": "fixture", "service": "web", "state": "RUNNING"},
                  ]}}
        self.queue.finish(claim, outcome, "PROBE_COMPLETE" if outcome == "SUCCEEDED" else "SSH_TIMEOUT",
                          result=result if outcome == "SUCCEEDED" else None)
        return job["id"]

    @contextmanager
    def transaction(self, *, write=True):
        with closing(sqlite3.connect(self.output / "migrated.sqlite3", autocommit=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.execute("COMMIT")

    def save(self, **kwargs):
        with self.transaction() as db:
            return save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER, **kwargs)

    def test_persists_exact_observation_and_audit_without_creating_a_job(self):
        value, tag = self.save()
        self.assertEqual(value["state"], "DRAFT")
        self.assertEqual(value["baseline"]["observation_id"], self.probe_id)
        self.assertEqual(value["backup_gate"], "NOT_EVALUATED")
        self.assertEqual(value["execution"], "BLOCKED")
        self.assertNotIn("scope_digest", value["baseline"])
        with self.transaction(write=False) as db:
            self.assertEqual(get_draft(db, self.auth, self.token, value["id"]), (value, tag))
            stored = db.execute("SELECT baseline FROM change_plan_drafts").fetchone()[0]
            bound = dict(value)
            del bound["plan_hash"]
            bound["baseline"] = json.loads(stored)
            self.assertEqual(value["plan_hash"], checksum(bound))
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT event FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0],
                             "change_plan.draft_saved")
            Store.verify_audit_connection(db)

    def test_pins_latest_completed_job_even_when_probe_timestamps_match(self):
        newest = self.probe()
        self.assertNotEqual(newest, self.probe_id)
        self.output = self.directory / "latest"
        rehearse(self.store, self.output, to_schema=3)
        self.assertEqual(self.save()[0]["baseline"]["observation_id"], newest)
        self.probe("FAILED")
        self.output = self.directory / "failed"
        rehearse(self.store, self.output, to_schema=3)
        with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
            self.save()

    def test_rechecks_scoped_permissions_on_every_revision(self):
        self.create_user(grants=[{"permission": permission, "resource_id": SCOPE}
                                 for permission in ("vps:read", "vps:restart")])
        client = self.other_client("operator")
        token = client.cookies[COOKIE]
        csrf = client.get("/api/v1/auth/session").json()["csrf_token"]
        self.output = self.directory / "scoped"
        rehearse(self.store, self.output, to_schema=3)
        with self.transaction() as db:
            draft, tag = save_draft(db, self.auth, token, csrf, SCOPE, CONTAINER)
            db.execute("DELETE FROM grants WHERE permission='vps:restart'")
        with self.assertRaisesRegex(Denied, "FORBIDDEN"):
            with self.transaction() as db:
                save_draft(db, self.auth, token, csrf, SCOPE, CONTAINER, draft_id=draft["id"], if_match=tag)
        with self.transaction() as db:
            self.assertEqual(get_draft(db, self.auth, token, draft["id"])[0]["revision"], 1)
            db.execute("DELETE FROM grants WHERE permission='vps:read'")
        with self.assertRaisesRegex(Denied, "RESOURCE_NOT_FOUND"):
            with self.transaction(write=False) as db:
                get_draft(db, self.auth, token, draft["id"])

    def test_concurrent_revision_requires_exact_strong_etag(self):
        value, tag = self.save()
        with self.assertRaisesRegex(Denied, "IF_MATCH_REQUIRED"):
            self.save(draft_id=value["id"])
        with self.assertRaisesRegex(Denied, "STALE_REVISION"):
            self.save(draft_id=value["id"], if_match="W/" + tag)

        def refresh(_):
            try:
                return self.save(draft_id=value["id"], if_match=tag)[0]["revision"]
            except Denied as error:
                return error.status

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(refresh, (1, 2)), (2, 412))
        with self.transaction(write=False) as db:
            self.assertEqual([row[0] for row in db.execute("SELECT revision FROM change_plan_drafts ORDER BY revision")], [1, 2])

    def test_refuses_expired_observation_bad_csrf_and_cross_target_refresh(self):
        with self.transaction() as db:
            with self.assertRaisesRegex(Denied, "CSRF_REQUIRED"):
                save_draft(db, self.auth, self.token, "invalid", SCOPE, CONTAINER)
        value, tag = self.save()
        with self.transaction() as db:
            with self.assertRaisesRegex(Denied, "RESOURCE_NOT_FOUND"):
                save_draft(db, self.auth, self.token, self.csrf, OTHER, CONTAINER,
                           draft_id=value["id"], if_match=tag)
        self.now += 301
        with self.assertRaisesRegex(Denied, "FRESH_OBSERVATION_REQUIRED"):
            self.save(draft_id=value["id"], if_match=tag)
        with self.transaction(write=False) as db:
            self.assertEqual(get_draft(db, self.auth, self.token, value["id"])[0]["revision"], 1)

    def test_failed_audit_write_rolls_back_draft(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.transaction() as db:
                db.execute("""CREATE TEMP TRIGGER fixture_outbox_failure BEFORE INSERT ON outbox
                              BEGIN SELECT RAISE(ABORT, 'fixture outbox unavailable'); END""")
                save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER)
        with self.transaction(write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM change_plan_drafts").fetchone()[0], 0)
            Store.verify_audit_connection(db)

    def test_live_schema_two_rejects_draft_writes(self):
        with self.assertRaisesRegex(Denied, "CHANGE_PLAN_SCHEMA_REQUIRES_VERIFIED_MIGRATION"):
            with self.store.write() as db:
                save_draft(db, self.auth, self.token, self.csrf, SCOPE, CONTAINER)
