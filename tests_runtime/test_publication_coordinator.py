import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from hostorbit.admission import Admission
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import CONTROLLER_FILES
from hostorbit.runtime.controller_backup import sign_provenance
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.protocol import canonical, checksum
from hostorbit.runtime.publication import Publisher
from hostorbit.runtime.sftp_publication import completion
from hostorbit.runtime.storage import new_private_file
from test_sftp_publication import destination


class PublicationCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.writers = Admission.initialize(self.root / "writers", owner=os.geteuid())
        self.coordinator = Coordinator.initialize(self.root / "gate/snapshots", self.writers)
        self.store = Store.initialize(self.root / "app/controller.sqlite3")
        self.store.writers = self.writers
        self.key = SigningKey.generate()
        new_private_file(self.root / "gate.pub", bytes(self.key.verify_key))
        self.cfg = {"writer_directory": str(self.writers.directory), "supervisor_directory": str(self.root / "gate"),
                    "public_verify_key": str(self.root / "gate.pub"), "database": str(self.store.path), "app_uid": os.geteuid()}
        self.id = identifier()
        self.directory = self.coordinator.directory / "captures" / self.id
        self.directory.mkdir(mode=0o700, parents=True)
        for phase in ("REQUESTED", "CLOSING_ADMISSION", "SHORT_BARRIER", "BARRIER_RELEASED", "SEALED", "SIGNED"):
            self.coordinator._transition(self.id, phase)
        new_private_file(self.directory / "controller.age", os.urandom(2048))
        manifest = {"v": 1, "type": "controller.snapshot", "snapshot_id": self.id, "source_instance": self.id,
                    "gate_epoch": 1, "schema": 2, "audit_head": "0" * 64, "audit_sequence": 0,
                    "boot_id": "12345678-1234-1234-1234-123456789abc", "monotonic_ns": 1,
                    "captured_utc": int(time.time()), "time_trusted": False, "source_commit": "a" * 40, "pin_sha256": "b" * 64,
                    "files": [{"path": name, "size": 1, "sha256": "c" * 64} for name in sorted(CONTROLLER_FILES)]}
        # This fixture tests Root lifecycle/provenance only; protocol tests cover
        # transfer contents and the installed lab uses a real encrypted archive.
        recipient = "age1" + "q" * 58
        self.envelope = sign_provenance(manifest, recipient, self.directory / "controller.age", self.key)
        new_private_file(self.directory / "provenance.json", canonical(self.envelope))
        self.target = self.root / "target.json"
        new_private_file(self.target, canonical(destination()))
        self.calls = []

        def runner(config, directory, snapshot_id, target, envelope):
            self.assertEqual(self.writers.state()["phase"], "OPEN")
            self.calls.append(snapshot_id)
            # Network upload must not hold the business writer barrier.
            with self.store.write() as db:
                self.store.event(db, at=1, actor="fixture", kind="during.upload", target="controller", outcome="SUCCEEDED", correlation=self.id)
            value = completion(target, snapshot_id, envelope["claims"], canonical(envelope))
            return {**value, "marker_sha256": checksum(value), "remote_path": target.value["directory"] + "/" + snapshot_id, "verified": True}
        self.publisher = Publisher(self.cfg, target_path=self.target, owner=os.geteuid(), runner=runner)

    def phase(self):
        with self.coordinator.journal.connect() as db:
            return db.execute("SELECT phase FROM snapshots WHERE id=?", (self.id,)).fetchone()[0]

    def test_confirmed_publication_is_durable_and_audit_is_idempotent_after_snapshot(self):
        result = self.publisher.publish(self.id)
        self.assertEqual(self.phase(), "PUBLISHED")
        self.assertTrue(result["remote_verified"])
        self.assertFalse(result["restore_verified"])
        self.assertEqual(result["backup_gate"], "DENIED")
        self.publisher.publish(self.id)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE event='backup.published'").fetchone()[0], 1)
        self.store.verify_audit()

    def test_failed_or_interrupted_upload_is_not_completion_and_can_reconcile(self):
        original = self.publisher.runner
        self.publisher.runner = lambda *_: (_ for _ in ()).throw(Denied("SFTP_TIMEOUT"))
        with self.assertRaisesRegex(Denied, "SFTP_TIMEOUT"):
            self.publisher.publish(self.id)
        self.assertEqual(self.phase(), "FAILED")
        self.assertEqual(self.writers.state()["phase"], "OPEN")
        self.assertFalse((self.directory / "publication-receipt.json").exists())
        self.publisher.runner = original
        self.publisher.publish(self.id)
        self.assertEqual(self.phase(), "PUBLISHED")

    def test_retry_cannot_switch_destination_or_signed_source(self):
        self.publisher.publish(self.id)
        changed = destination()
        changed["directory"] = "/other"
        self.target.write_bytes(canonical(changed))
        with self.assertRaisesRegex(Denied, "PUBLICATION_TARGET_OR_SOURCE_CHANGED"):
            self.publisher.publish(self.id)
        self.assertEqual(len(self.calls), 1)

    def test_false_helper_receipt_cannot_promote_or_append_success(self):
        self.publisher.runner = lambda *_: {"verified": True}
        with self.assertRaisesRegex(Denied, "PUBLICATION_RECEIPT_INVALID"):
            self.publisher.publish(self.id)
        self.assertEqual(self.phase(), "FAILED")
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM audit").fetchone()[0], 0)

    def test_control_journal_failure_closes_admission_before_network(self):
        with patch.object(self.publisher.coordinator, "_transition", side_effect=OSError("fixture ENOSPC")):
            with self.assertRaises(OSError):
                self.publisher.publish(self.id)
        self.assertEqual(self.calls, [])
        self.assertNotEqual(self.writers.state()["phase"], "OPEN")
        self.coordinator.recover()
        self.assertEqual(self.phase(), "FAILED")
        self.assertEqual(self.writers.state()["phase"], "OPEN")


if __name__ == "__main__":
    unittest.main()
