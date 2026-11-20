import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from deploy.application_update import apply_update
from deploy.build_update_release import build_release
from deploy.controller_restore_attestation import CHECKS, KIND, sign_restore
from deploy.prepare_migration import prepare_migration
from hostorbit.admission import Admission
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.migrations import rehearse
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.ipc import Peer
from fixtures import policy, trusted_time


class ApplicationUpdateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        writers = Admission.initialize(self.root / "writers", owner=os.geteuid())
        writers.publish("OPEN")
        self.store = Store.initialize(self.root / "app" / "controller.sqlite3", schema=2)
        review = self.root / "review"
        rehearse(self.store, review, to_schema=3)
        clock = lambda: 1_800_000_000
        self.authority = Authority.initialize(self.root / "gate", policy(), clock=clock,
                                              time_health=trusted_time(self.root / "time", clock))
        self.authority.journal.writers = writers
        self.addCleanup(self.authority.close)
        instance = self.authority.time_report()["claims"]["authority_id"]
        self.config = {"database": self.store.path, "app_uid": os.geteuid(),
                       "writer_directory": writers.directory, "public_verify_key": self.root / "gate" / "verify.key"}
        self.directory = self.root / "update"
        self.release = self.root / "release"
        archive = self.root / "updater.tar.zst"
        archive.write_bytes(b"disposable updater")
        signer = SigningKey.generate()
        self.key = bytes(signer.verify_key)
        self.compatibility = dict(installed="1.1.0", bootstrap="1.0.0", minimum_release="1.0.0", schema=2, vault_format=1)
        self.digests = {name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")}
        build_release(self.release, archive, signer, release_version="1.2.0", schema_to=3,
                      images=self.digests, **self.compatibility)
        self.images = {name: "registry.example.test/hostorbit/" + name + "@" + self.digests[name]
                       for name in ("api", "worker")}
        snapshot = identifier()
        owner = SigningKey.generate()
        evidence = b"fixture evidence"
        backup = {"status": "FRESH_BACKUP_COPY_VERIFIED", "snapshot_id": snapshot, "source_schema": 2,
                  "source_instance": instance, "target_id": identifier(), "marker_sha256": "b" * 64,
                  "maximum_age_seconds": 15, "backup_gate": "DENIED", "restore_verified": False,
                  "failure_domain_verified": False}
        proof = sign_restore({"v": 1, "type": KIND, "source_instance": instance, "snapshot_id": snapshot,
                              "marker_sha256": backup["marker_sha256"], "schema": 2,
                              "tested_at": 1_799_999_999, "checks": dict.fromkeys(CHECKS, True)}, evidence, owner)
        self.inputs = {**self.compatibility, "review": review, "snapshot_id": snapshot,
                       "downloaded_copy": self.root / "downloaded",
                       "restore": {"record": proof, "evidence": evidence, "owner_key": bytes(owner.verify_key)}}
        self.enterContext(patch("deploy.prepare_migration.check_publication", return_value=backup))
        plan = prepare_migration(self.config, self.release, self.key, self, owner=os.geteuid(), **self.inputs)
        self.approval = {"plan_id": identifier(), "revision": 1, "approval_id": identifier(),
                         "plan_sha256": plan["plan_sha256"]}
        self.calls = []
        self.document = b"old"
        self.failure = None

    def call(self, operation, request):
        return self.authority.dispatch("updater", Peer(1, 0, 0), operation, request)

    def state(self):
        with self.authority.journal.connect() as db:
            return db.execute("SELECT state FROM gate").fetchone()[0]

    def schema(self):
        with self.store.connect(readonly=True) as db:
            return db.execute("PRAGMA user_version").fetchone()[0]

    def update(self):
        return apply_update(self.config, self.release, self.key, self, self.approval, self.images,
                            self, self.directory, inputs=self.inputs, owner=os.geteuid())

    def stage(self, images, digests):
        self.assertEqual(self.state(), "NORMAL")
        self.assertEqual(images, self.images)
        self.assertEqual(digests, self.digests)
        return b"old", b"new"

    def fence_start(self):
        self.calls.append("fence")
        (self.directory / "fixture.blocked").touch()

    def stop(self):
        self.assertEqual(self.state(), "MAINTENANCE")
        self.assertTrue((self.directory / "fixture.blocked").exists())
        self.calls.append("stop")

    def publish(self, document):
        self.calls.append(("publish", document))
        self.document = document
        if self.failure == "kill" and document == b"new":
            os.kill(os.getpid(), signal.SIGKILL)

    def start(self):
        self.calls.append(("start", self.document, self.schema()))
        (self.directory / "fixture.blocked").unlink()
        if self.failure == "start":
            raise Denied("FIXTURE_START_FAILED")

    def test_migrates_and_switches_services_before_resuming(self):
        self.assertEqual(self.update()["schema"], 3)
        self.assertEqual(self.calls, ["fence", "stop", ("publish", b"new"), ("start", b"new", 3)])
        self.assertEqual(self.state(), "NORMAL")
        self.assertFalse((self.directory / "pending.json").exists())
        with self.store.connect(readonly=True) as db:
            row = db.execute("SELECT event,details FROM audit").fetchone()
            self.assertEqual(row["event"], "database.schema_migrated")
            self.assertFalse(json.loads(row["details"])["rehearsal"])
            Store.verify_audit_connection(db)

    def test_error_before_commit_rolls_back_sqlite_and_restores_old_services(self):
        with patch.object(Store, "event", side_effect=Denied("FIXTURE_AUDIT_WRITE_FAILED")):
            with self.assertRaisesRegex(Denied, "FIXTURE_AUDIT_WRITE_FAILED"):
                self.update()
        self.assertEqual(self.schema(), 2)
        self.assertEqual(self.calls[-1], ("start", b"old", 2))
        self.assertEqual(self.state(), "MAINTENANCE")
        self.assertTrue((self.directory / "pending.json").is_file())

    def test_error_after_commit_fences_without_downgrading(self):
        self.failure = "start"
        with self.assertRaisesRegex(Denied, "FIXTURE_START_FAILED"):
            self.update()
        self.assertEqual(self.schema(), 3)
        self.assertEqual(self.calls[-2:], ["fence", "stop"])
        self.assertTrue((self.directory / "pending.json").is_file())
        self.assertEqual(self.state(), "MAINTENANCE")

    def test_crash_after_commit_blocks_repeat_and_preserves_migrated_database(self):
        self.failure = "kill"
        process = multiprocessing.get_context("fork").Process(target=self.update)
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join(5)
            self.fail("Timed out waiting for commit")
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        self.assertEqual(self.schema(), 3)
        self.assertTrue((self.directory / "fixture.blocked").is_file())
        self.authority.recover()
        self.assertEqual(self.state(), "RECOVERY_HOLD")
        with self.assertRaisesRegex(Denied, "APPLICATION_UPDATE_RECOVERY_REQUIRED"):
            self.update()
