import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hostorbit.admission import Admission
from hostorbit.database import Store
from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import CONTROLLER_FILES
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.clock import NANOSECOND, clocks
from hostorbit.runtime.controller_backup import sign_provenance
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.migration_backup import check_publication
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.publication import Publisher
from hostorbit.runtime.sftp_publication import publish_session
from hostorbit.runtime.storage import new_private_file
from test_sftp_publication import Remote, destination


class PublicationFixture:
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        writers = Admission.initialize(root / "writers", owner=os.geteuid())
        store = Store.initialize(root / "app/controller.sqlite3")
        authority = Authority.initialize(root / "gate", Policy([]))
        self.addCleanup(authority.close)
        with authority.journal.connect() as db:
            instance = db.execute("SELECT instance_id FROM gate").fetchone()[0]
        self.coordinator = Coordinator.initialize(root / "gate/snapshots", writers)
        self.config = {"writer_directory": str(writers.directory), "supervisor_directory": str(authority.directory),
                       "public_verify_key": str(authority.directory / "verify.key"), "database": str(store.path),
                       "app_uid": os.geteuid()}
        self.target = root / "target.json"
        new_private_file(self.target, canonical(destination()))

        (self.coordinator.directory / "captures").mkdir(mode=0o700)

        def capture(snapshot_id):
            self.capture = self.coordinator.directory / "captures" / snapshot_id
            self.capture.mkdir(mode=0o700, parents=True)
            ciphertext = self.capture / "controller.age"
            new_private_file(ciphertext, os.urandom(150000))
            now = clocks()
            self.manifest = {"v": 1, "type": "controller.snapshot", "snapshot_id": snapshot_id,
                             "source_instance": instance, "gate_epoch": 0, "schema": 3, "audit_head": "0" * 64,
                             "audit_sequence": 0, "boot_id": now["boot_id"], "monotonic_ns": now["mono_ns"],
                             "captured_utc": 0, "time_trusted": False, "source_commit": "a" * 40,
                             "pin_sha256": "b" * 64,
                             "files": [{"path": name, "size": 1, "sha256": "c" * 64} for name in sorted(CONTROLLER_FILES)]}
            envelope = sign_provenance(self.manifest, "age1" + "q" * 58, ciphertext, authority.key)
            new_private_file(self.capture / "provenance.json", canonical(envelope))

        self.capture_fixture = capture
        self.signing_key = authority.key
        self.snapshot = self.new_snapshot()
        self.journal = authority.journal

        self.remote = Remote()

        def runner(config, directory, snapshot_id, target, envelope, *, verify_only=False):
            return asyncio.run(publish_session(self.remote, target, snapshot_id, directory / "controller.age",
                                               envelope["claims"], canonical(envelope), lambda: None, verify_only=verify_only))

        self.publisher = Publisher(self.config, target_path=self.target, owner=os.geteuid(), runner=runner)

    def new_snapshot(self):
        snapshot, _ = self.coordinator.snapshot(lambda: True, self.capture_fixture)
        for phase in ("SEALED", "SIGNED"):
            self.coordinator._transition(snapshot, phase)
        return snapshot


class MigrationBackupTests(PublicationFixture, unittest.TestCase):
    def check(self, **options):
        return check_publication(self.config, self.snapshot, target_path=self.target, owner=os.geteuid(), **options)

    def download(self):
        self.publisher.publish(self.snapshot)
        directory = self.target.parent / "download"
        directory.mkdir(mode=0o700)
        for remote_path, data in self.remote.files.items():
            new_private_file(directory / Path(remote_path).name, data)
        return directory

    def test_published_snapshot_reports_preflight_without_authorizing_migration(self):
        self.publisher.publish(self.snapshot)
        result = self.check()
        self.assertEqual(result["status"], "FRESH_PUBLICATION_RECORDED")
        self.assertEqual(result["snapshot_id"], self.snapshot)
        self.assertEqual(result["backup_gate"], "DENIED")
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["failure_domain_verified"])

    def test_signed_only_and_failed_publications_are_denied(self):
        with self.assertRaisesRegex(Denied, "MIGRATION_PUBLICATION_NOT_RECORDED"):
            self.check()
        self.publisher.publish(self.snapshot)
        self.coordinator._transition(self.snapshot, "FAILED", "TEST")
        with self.assertRaisesRegex(Denied, "MIGRATION_PUBLICATION_NOT_RECORDED"):
            self.check()

    def test_exact_thirty_minute_bound_includes_suspend_and_ignores_wall_clock(self):
        self.publisher.publish(self.snapshot)
        with self.coordinator.journal.connect() as db:
            start = db.execute("SELECT monotonic_ns FROM transitions WHERE phase='SHORT_BARRIER'").fetchone()[0]
        now = {**clocks(), "tick_ns": start + 1800 * NANOSECOND, "wall_ns": -1}
        with patch("hostorbit.runtime.migration_backup.clocks", return_value=now):
            self.assertEqual(self.check()["maximum_age_seconds"], 1800)
            now["tick_ns"] += 1
            with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_STALE"):
                self.check()
            now["boot_id"] = "00000000-0000-0000-0000-000000000000"
            with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_CLOCK_UNVERIFIED"):
                self.check()

    def test_mismatched_target_and_modified_receipt_are_denied(self):
        self.publisher.publish(self.snapshot)
        self.target.write_bytes(canonical({**destination(), "directory": "/different"}))
        with self.assertRaisesRegex(Denied, "MIGRATION_PUBLICATION_BINDING_INVALID"):
            self.check()
        self.target.write_bytes(canonical(destination()))
        receipt = self.capture / "publication-receipt.json"
        receipt.write_bytes(canonical({**json.loads(receipt.read_bytes()), "verified": 1}))
        with self.assertRaisesRegex(Denied, "MIGRATION_PUBLICATION_BINDING_INVALID"):
            self.check()

    def test_signed_backup_from_another_controller_or_schema_is_denied(self):
        self.publisher.publish(self.snapshot)
        with self.journal.write() as db:
            db.execute("UPDATE gate SET instance_id=? WHERE id=1", (self.snapshot,))
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_SOURCE_MISMATCH"):
            self.check()
        with self.journal.write() as db:
            db.execute("UPDATE gate SET instance_id=? WHERE id=1", (self.manifest["source_instance"],))
        store = Store(self.config["database"])
        with store.write() as db:
            db.execute("PRAGMA user_version=1")
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_SOURCE_MISMATCH"):
            self.check()

    def test_tampered_provenance_is_denied(self):
        self.publisher.publish(self.snapshot)
        provenance = self.capture / "provenance.json"
        envelope = json.loads(provenance.read_bytes())
        envelope["claims"]["manifest"]["captured_utc"] = 1
        provenance.write_bytes(canonical(envelope))
        with self.assertRaisesRegex(Denied, "ARCHIVE_PROVENANCE_INVALID"):
            self.check()

    def test_downloaded_copy_matches_publication_without_local_ciphertext(self):
        downloaded = self.download()
        (self.capture / "controller.age").unlink()
        result = self.check(downloaded_copy=downloaded)
        self.assertEqual(result["status"], "FRESH_BACKUP_COPY_VERIFIED")
        self.assertEqual(result["marker_sha256"], self.check()["marker_sha256"])
        self.assertEqual(result["backup_gate"], "DENIED")
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["failure_domain_verified"])

    def test_each_downloaded_member_is_bound_to_the_publication(self):
        downloaded = self.download()
        for name in ("COMPLETE", "provenance.json", "controller.age"):
            with self.subTest(name=name):
                member = downloaded / name
                original = member.read_bytes()
                member.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_MISMATCH"):
                    self.check(downloaded_copy=downloaded)
                member.write_bytes(original)

    def test_missing_or_unexpected_members_are_denied(self):
        downloaded = self.download()
        extra = downloaded / "another-file"
        new_private_file(extra, b"extra")
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_INCOMPLETE"):
            self.check(downloaded_copy=downloaded)
        extra.unlink()
        (downloaded / "COMPLETE").unlink()
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_INCOMPLETE"):
            self.check(downloaded_copy=downloaded)

    def test_downloaded_member_must_be_a_private_regular_file(self):
        downloaded = self.download()
        member = downloaded / "controller.age"
        member.chmod(0o644)
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_UNSAFE"):
            self.check(downloaded_copy=downloaded)
        member.unlink()
        member.symlink_to(self.capture / "controller.age")
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_UNSAFE"):
            self.check(downloaded_copy=downloaded)

    def test_signed_copy_must_still_meet_the_freshness_limit(self):
        downloaded = self.download()
        with self.coordinator.journal.connect() as db:
            start = db.execute("SELECT monotonic_ns FROM transitions WHERE phase='SHORT_BARRIER'").fetchone()[0]
        now = {**clocks(), "tick_ns": start + 1800 * NANOSECOND + 1}
        with patch("hostorbit.runtime.migration_backup.clocks", return_value=now):
            with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_STALE"):
                self.check(downloaded_copy=downloaded)

    def test_truncated_ciphertext_is_denied(self):
        downloaded = self.download()
        ciphertext = downloaded / "controller.age"
        ciphertext.write_bytes(ciphertext.read_bytes()[:-1])
        with self.assertRaisesRegex(Denied, "MIGRATION_BACKUP_COPY_MISMATCH"):
            self.check(downloaded_copy=downloaded)
