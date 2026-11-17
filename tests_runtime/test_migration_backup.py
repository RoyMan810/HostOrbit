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
from hostorbit.runtime.protocol import canonical, checksum
from hostorbit.runtime.publication import Publisher
from hostorbit.runtime.sftp_publication import completion
from hostorbit.runtime.storage import new_private_file
from test_sftp_publication import destination


class MigrationBackupTests(unittest.TestCase):
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
            new_private_file(ciphertext, os.urandom(2048))
            now = clocks()
            self.manifest = {"v": 1, "type": "controller.snapshot", "snapshot_id": snapshot_id,
                             "source_instance": instance, "gate_epoch": 0, "schema": 2, "audit_head": "0" * 64,
                             "audit_sequence": 0, "boot_id": now["boot_id"], "monotonic_ns": now["mono_ns"],
                             "captured_utc": 0, "time_trusted": False, "source_commit": "a" * 40,
                             "pin_sha256": "b" * 64,
                             "files": [{"path": name, "size": 1, "sha256": "c" * 64} for name in sorted(CONTROLLER_FILES)]}
            envelope = sign_provenance(self.manifest, "age1" + "q" * 58, ciphertext, authority.key)
            new_private_file(self.capture / "provenance.json", canonical(envelope))

        self.snapshot, _ = self.coordinator.snapshot(lambda: True, capture)
        for phase in ("SEALED", "SIGNED"):
            self.coordinator._transition(self.snapshot, phase)
        self.journal = authority.journal

        def runner(config, directory, snapshot_id, target, envelope):
            value = completion(target, snapshot_id, envelope["claims"], canonical(envelope))
            return {**value, "marker_sha256": checksum(value), "remote_path": target.value["directory"] + "/" + snapshot_id,
                    "verified": True}

        self.publisher = Publisher(self.config, target_path=self.target, owner=os.geteuid(), runner=runner)

    def check(self):
        return check_publication(self.config, self.snapshot, target_path=self.target, owner=os.geteuid())

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
