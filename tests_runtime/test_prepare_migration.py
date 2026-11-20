import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from deploy.build_update_release import build_release
from deploy.controller_restore_attestation import CHECKS, KIND, sign_restore
from deploy.prepare_migration import prepare_migration
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.migrations import rehearse
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.protocol import checksum
from fixtures import policy, trusted_time


class PrepareMigrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store.initialize(self.root / "database" / "controller.sqlite3", schema=2)
        self.review = self.root / "review"
        self.rehearsal = rehearse(self.store, self.review, to_schema=3)
        clock = lambda: 1_800_000_000
        self.gate = Authority.initialize(self.root / "gate", policy(), clock=clock,
                                         time_health=trusted_time(self.root / "time", clock))
        self.addCleanup(self.gate.close)
        with self.gate.journal.connect() as db:
            instance = db.execute("SELECT instance_id FROM gate").fetchone()[0]
        self.config = {"database": self.store.path, "app_uid": os.geteuid(),
                       "public_verify_key": self.root / "gate" / "verify.key"}
        self.archive = self.root / "updater.tar.zst"
        self.archive.write_bytes(b"fixture")
        self.signer = SigningKey.generate()
        self.release = self.root / "release"
        self.compatibility = dict(installed="1.1.0", bootstrap="1.0.0", minimum_release="1.0.0",
                                  schema=2, vault_format=1)
        self.signed = build_release(self.release, self.archive, self.signer, release_version="1.2.0",
                                    schema_to=3, images={name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")},
                                    **self.compatibility)
        self.snapshot = identifier()
        self.downloaded_copy = self.root / "downloaded"
        self.backup = {"status": "FRESH_BACKUP_COPY_VERIFIED", "snapshot_id": self.snapshot, "source_schema": 2,
                       "source_instance": instance, "target_id": identifier(), "marker_sha256": "b" * 64,
                       "maximum_age_seconds": 25, "backup_gate": "DENIED", "restore_verified": False,
                       "failure_domain_verified": False}
        # The SFTP reader and receipt checks have their own integration suite.
        self.check_backup = self.enterContext(patch("deploy.prepare_migration.check_publication", return_value=self.backup))

    def call(self, operation, payload):
        self.assertEqual((operation, payload), ("time.health", {}))
        return self.gate.time_report()

    def prepare(self, **options):
        return prepare_migration(self.config, self.release, bytes(self.signer.verify_key), self,
                                 review=self.review, snapshot_id=self.snapshot, downloaded_copy=self.downloaded_copy,
                                 owner=os.geteuid(), **self.compatibility, **options)

    def test_binds_release_live_rows_and_verified_backup_without_requesting_permission(self):
        before = self.store.path.read_bytes()
        report = self.prepare()
        self.assertEqual(report["status"], "MIGRATION_INPUTS_VERIFIED")
        self.assertEqual(report["plan_sha256"], checksum(report["plan"]))
        self.assertEqual(report["plan"]["release_sha256"], self.signed["release_sha256"])
        self.assertEqual(report["plan"]["source_rows_sha256"], self.rehearsal["source_rows_sha256"])
        self.assertEqual(report["plan"]["backup_marker_sha256"], self.backup["marker_sha256"])
        self.assertEqual((report["backup_gate"], report["live_apply"]), ("DENIED", "BLOCKED"))
        self.assertFalse(report["restore_verified"])
        self.assertEqual(self.store.path.read_bytes(), before)
        self.check_backup.assert_called_once_with(self.config, self.snapshot, downloaded_copy=self.downloaded_copy,
                                                 owner=os.geteuid())

    def test_rejects_even_valid_wal_writes_since_rehearsal(self):
        with self.store.write() as db:
            Store.event(db, at=1, actor="fixture", kind="fixture.changed", target="controller",
                        outcome="SUCCEEDED", correlation="fixture")
        with self.assertRaisesRegex(Denied, "MIGRATION_REHEARSAL_SOURCE_CHANGED"):
            self.prepare()

    def test_rejects_receipt_without_verified_copy_and_foreign_authority(self):
        self.backup["status"] = "FRESH_PUBLICATION_RECORDED"
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_REQUIRED"):
            self.prepare()
        self.backup.update(status="FRESH_BACKUP_COPY_VERIFIED", source_instance=identifier())
        with self.assertRaisesRegex(Denied, "MIGRATION_SUPERVISOR_UNAVAILABLE"):
            self.prepare()

    def test_rejects_busy_supervisor(self):
        with self.gate.journal.write() as db:
            db.execute("UPDATE gate SET state='RECOVERY_HOLD' WHERE id=1")
        with self.assertRaisesRegex(Denied, "MIGRATION_SUPERVISOR_UNAVAILABLE"):
            self.prepare()

    def restore(self, *, signer=None, **changes):
        signer = signer or SigningKey.generate()
        evidence = b"signed review of an isolated Controller restore"
        claims = {
            "v": 1, "type": KIND, "source_instance": self.backup["source_instance"],
            "snapshot_id": self.snapshot, "marker_sha256": self.backup["marker_sha256"],
            "schema": 2, "tested_at": 1_799_999_990, "checks": dict.fromkeys(CHECKS, True), **changes,
        }
        return {"record": sign_restore(claims, evidence, signer), "evidence": evidence,
                "owner_key": bytes(signer.verify_key)}

    def test_binds_the_owner_signature_without_opening_the_gate(self):
        plain = self.prepare()
        report = self.prepare(restore=self.restore())
        self.assertEqual(report["owner_restore_attestation"]["status"], "OWNER_RESTORE_ATTESTATION_VERIFIED")
        self.assertEqual(report["plan"]["restore_attestation_sha256"],
                         report["owner_restore_attestation"]["attestation_sha256"])
        self.assertNotEqual(report["plan_sha256"], plain["plan_sha256"])
        self.assertEqual(report["plan_sha256"], checksum(report["plan"]))
        self.assertEqual((report["backup_gate"], report["live_apply"]), ("DENIED", "BLOCKED"))

    def test_rejects_another_snapshot_changed_evidence_and_stale_proof(self):
        for restore, reason in (
            (self.restore(snapshot_id=identifier()), "CONTROLLER_RESTORE_ATTESTATION_SCOPE_MISMATCH"),
            ({**self.restore(), "evidence": b"edited"}, "CONTROLLER_RESTORE_EVIDENCE_CHANGED"),
            (self.restore(tested_at=1_799_990_000), "CONTROLLER_RESTORE_ATTESTATION_STALE"),
            (self.restore(signer=self.signer), "CONTROLLER_RESTORE_SEPARATE_OWNER_KEY_REQUIRED"),
            ({**self.restore(), "owner_key": bytes(SigningKey.generate().verify_key)},
             "CONTROLLER_RESTORE_ATTESTATION_INVALID"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(Denied, reason):
                self.prepare(restore=restore)
