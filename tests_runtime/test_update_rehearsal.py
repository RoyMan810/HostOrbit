from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from deploy.artifact import ArtifactError
from deploy.build_update_release import build_release
from deploy.rehearse_update import rehearse_update, select_slot
from hostorbit.database import Store
from hostorbit.migrations import rehearse


class UpdateRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.archive = self.root / "updater.tar.zst"
        self.archive.write_bytes(b"candidate fixture")
        self.signer = SigningKey.generate()
        self.release = self.root / "release"
        self.compatibility = dict(installed="1.1.0", bootstrap="1.0.0", minimum_release="1.0.0", schema=2, vault_format=1)

    def build(self, schema_to):
        return build_release(self.release, self.archive, self.signer, release_version="1.2.0",
                             schema_to=schema_to, images={name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")},
                             **self.compatibility)

    def execute(self, **options):
        return rehearse_update(self.release, bytes(self.signer.verify_key), **self.compatibility, **options)

    def test_atomic_switch_checks_signed_slot_then_restores_a(self):
        signed = self.build(2)
        report = self.execute()
        self.assertEqual(report["status"], "UPDATE_REHEARSAL_PASSED")
        self.assertEqual(report["release_sha256"], signed["release_sha256"])
        self.assertTrue(report["candidate_verified_after_switch"])
        self.assertTrue(report["rollback_verified"])
        self.assertFalse(report["applied"])

    def test_health_failure_is_reported_after_rollback(self):
        self.build(2)
        def switch_and_corrupt(root, slot):
            select_slot(root, slot)
            if slot == "B":
                (root / "B" / "release.sig").write_bytes(b"bad signature")

        with patch("deploy.rehearse_update.select_slot", side_effect=switch_and_corrupt):
            report = self.execute()
        self.assertEqual(report["status"], "UPDATE_REHEARSAL_ROLLED_BACK")
        self.assertFalse(report["candidate_verified_after_switch"])
        self.assertTrue(report["rollback_verified"])

    def test_schema_change_requires_matching_review_and_preserves_source(self):
        self.build(3)
        with self.assertRaisesRegex(ArtifactError, "UPDATE_MIGRATION_REHEARSAL_REQUIRED"):
            self.execute()
        source = Store.initialize(self.root / "live" / "controller.sqlite3", schema=2)
        before = source.path.read_bytes()
        migration = self.root / "migration"
        rehearse(source, migration, to_schema=3)
        self.assertTrue(self.execute(migration=migration)["migration_verified"])
        self.assertEqual(source.path.read_bytes(), before)

    def test_tampered_package_is_denied_before_switch(self):
        self.build(2)
        (self.release / "hostorbit-updater-linux-amd64-1.2.0.tar.zst").write_bytes(b"invalid package")
        with self.assertRaisesRegex(ArtifactError, "UPDATE_UPDATER_DIGEST_MISMATCH"):
            self.execute()
