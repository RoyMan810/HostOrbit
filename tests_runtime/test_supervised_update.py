import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from deploy.build_update_release import build_release
from deploy.rehearse_update import select_slot
from deploy.supervised_update import select_update, slot_name
from hostorbit.database import identifier
from hostorbit.errors import Denied
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.ipc import Peer
from fixtures import policy, trusted_time


class SupervisedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.slots = self.root / "slots"
        self.signer = SigningKey.generate()
        self.archive = self.root / "updater.tar.zst"
        self.archive.write_bytes(b"disposable updater fixture")
        clock = lambda: 1_800_000_000
        self.authority = Authority.initialize(self.root / "gate", policy(), clock=clock,
                                              time_health=trusted_time(self.root / "time", clock))
        self.addCleanup(self.authority.close)
        self.calls = []

    def call(self, operation, request):
        self.calls.append(operation)
        return self.authority.dispatch("updater", Peer(1, 0, 0), operation, request)

    def state(self):
        with self.authority.journal.connect() as db:
            return db.execute("SELECT state FROM gate").fetchone()[0]

    def build(self, release, installed, schema_to=3):
        destination = self.root / release
        report = build_release(destination, self.archive, self.signer, release_version=release, installed=installed,
                               bootstrap="1.0.0", minimum_release="1.0.0", schema=3, schema_to=schema_to, vault_format=1,
                               images={name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")})
        approval = {"plan_id": identifier(), "revision": 1, "approval_id": identifier(),
                    "release_sha256": report["release_sha256"]}
        return destination, approval

    def apply(self, source, approval, installed):
        return select_update(source, self.slots, bytes(self.signer.verify_key), self, approval, installed=installed,
                             bootstrap="1.0.0", minimum_release="1.0.0", schema=3, vault_format=1)

    def test_checks_ticket_and_selects_a_then_b_with_real_authority(self):
        first, approval = self.build("1.2.0", "1.1.0")
        self.assertEqual(self.apply(first, approval, "1.1.0")["slot"], "A")
        self.assertEqual(self.state(), "NORMAL")
        self.assertEqual(self.calls, ["time.anchor", "update.quiesce", "update.maintenance", "update.resuming", "update.normal"])
        self.assertFalse((self.slots / "pending.json").exists())

        second, approval = self.build("1.3.0", "1.2.0")
        self.assertEqual(self.apply(second, approval, "1.2.0")["slot"], "B")
        self.assertEqual(slot_name(self.slots), "B")
        self.assertTrue((self.slots / "A" / "release.json").is_file())
        with self.assertRaisesRegex(Denied, "UPDATE_BASELINE_CHANGED"):
            self.apply(second, approval, "1.2.0")

    def test_wrong_approval_or_schema_is_denied_before_gate(self):
        source, approval = self.build("1.2.0", "1.1.0")
        with self.assertRaisesRegex(Denied, "UPDATE_APPROVAL_MISMATCH"):
            self.apply(source, {**approval, "release_sha256": "b" * 64}, "1.1.0")
        migration, migration_approval = self.build("1.3.0", "1.1.0", schema_to=4)
        with self.assertRaisesRegex(Denied, "UPDATE_SCHEMA_CHANGE_BLOCKED"):
            self.apply(migration, migration_approval, "1.1.0")
        self.assertIsNone(slot_name(self.slots))
        self.assertEqual(self.calls, [])

    def test_failed_postcheck_restores_prior_slot_and_blocks_retry(self):
        source, approval = self.build("1.2.0", "1.1.0")
        self.apply(source, approval, "1.1.0")
        candidate, approval = self.build("1.3.0", "1.2.0")

        def corrupt_after_switch(root, target):
            select_slot(root, target)
            if target == "B":
                (root / "B" / "release.sig").write_bytes(b"bad signature")

        with patch("deploy.supervised_update.select_slot", side_effect=corrupt_after_switch):
            with self.assertRaisesRegex(RuntimeError, "ARTIFACT_SIGNATURE_INVALID"):
                self.apply(candidate, approval, "1.2.0")
        self.assertEqual(slot_name(self.slots), "A")
        self.assertTrue((self.slots / "pending.json").is_file())
        self.assertEqual(self.state(), "MAINTENANCE")
        with self.assertRaisesRegex(Denied, "UPDATE_RECOVERY_REQUIRED"):
            self.apply(candidate, approval, "1.2.0")
        self.authority.recover()
        self.assertEqual(self.state(), "RECOVERY_HOLD")

    def test_process_death_after_switch_keeps_durable_pending_gate(self):
        base, approval = self.build("1.2.0", "1.1.0")
        self.apply(base, approval, "1.1.0")
        candidate, approval = self.build("1.3.0", "1.2.0")

        def update_then_kill():
            def timed_switch(root, target):
                select_slot(root, target)
                os.kill(os.getpid(), signal.SIGKILL)

            with patch("deploy.supervised_update.select_slot", side_effect=timed_switch):
                self.apply(candidate, approval, "1.2.0")

        process = multiprocessing.get_context("fork").Process(target=update_then_kill)
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join(5)
            self.fail("Timed out before the updater switched")
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        self.assertEqual(slot_name(self.slots), "B")
        self.assertTrue((self.slots / "pending.json").is_file())
        self.authority.recover()
        self.assertEqual(self.state(), "RECOVERY_HOLD")
        with self.assertRaisesRegex(Denied, "UPDATE_RECOVERY_REQUIRED"):
            self.apply(candidate, approval, "1.2.0")
