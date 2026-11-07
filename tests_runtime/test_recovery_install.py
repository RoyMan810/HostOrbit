import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hostorbit.errors import Denied
from hostorbit.runtime import recovery_install
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.storage import protected_bytes
import test_rescue as rescue_fixture


class RecoveryInstallationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = rescue_fixture.RescueTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        review = self.fixture.pack()
        self.fixture.accept(review["bundle_sha256"])
        self.state = self.fixture.root / "target-state"
        self.data = self.fixture.root / "target-data"
        self.enterContext(patch.object(recovery_install, "_require_root"))
        self.enterContext(patch.object(recovery_install, "_trusted_path", side_effect=lambda p: Path(p)))
        self.enterContext(patch.object(recovery_install, "_read", side_effect=lambda p, maximum=65536:
            protected_bytes(p, owner=os.geteuid(), maximum=maximum, exact_mode=0o600)))
        load = Policy.load
        self.enterContext(patch.object(Policy, "load", side_effect=lambda p, **_: load(p, owner=os.geteuid())))
        self.enterContext(patch.object(recovery_install.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=self.fixture.fixture.dek)))

    def test_complete_local_import_is_eligible_without_new_owner_or_source_age_gate(self):
        checked = recovery_install.check(self.state)
        self.assertEqual(checked["status"], "RECOVERY_INSTALLATION_ELIGIBLE")
        self.assertEqual(checked["mode"], "READ_ONLY_RECOVERY")
        self.assertEqual(checked["schema"], 2)
        self.assertFalse((self.state / "installation.claim.json").exists())

    def test_consumed_installation_and_incomplete_import_cannot_be_reused(self):
        (self.state / "installation.claim.json").write_bytes(b"{}")
        with self.assertRaisesRegex(Denied, "RECOVERY_INSTALLATION_CONSUMED"):
            recovery_install.check(self.state)
        (self.state / "installation.claim.json").unlink()
        from hostorbit.runtime.storage import Journal
        with Journal(self.state / "recovery.sqlite3").write() as db:
            db.execute("UPDATE request SET state='FAILED'")
        with self.assertRaisesRegex(Denied, "RECOVERY_IMPORT_NOT_COMPLETE"):
            recovery_install.check(self.state)

    def test_active_or_foreign_authority_cannot_boot_as_restored_controller(self):
        from hostorbit.runtime.storage import Journal
        with Journal(self.data / "control-gate/gate.sqlite3").write() as db:
            db.execute("UPDATE gate SET activated=1")
        with self.assertRaisesRegex(Denied, "RECOVERY_AUTHORITY_INVALID"):
            recovery_install.check(self.state)

    def test_missing_readonly_profile_and_changed_receipt_refuse(self):
        path = self.data / "recovery.json"
        receipt = json.loads(path.read_bytes())
        receipt["bundle_sha256"] = "0" * 64
        path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(Denied, "RECOVERY_RECEIPT_INVALID"):
            recovery_install.check(self.state)

    def test_wrong_new_host_os_seal_cannot_initialize_a_new_vault(self):
        recovery_install.subprocess.run.return_value = SimpleNamespace(returncode=1, stdout=b"")
        with self.assertRaisesRegex(Denied, "RECOVERY_HOST_CREDENTIAL_UNAVAILABLE"):
            recovery_install.check(self.state)

    def test_corrupt_ciphertext_or_changed_signed_pin_is_rejected(self):
        objects = self.data / "vault/objects"
        obj = next(objects.iterdir())
        obj.write_bytes(b"corrupt")
        with self.assertRaisesRegex(Denied, "RECOVERY_VAULT_INVALID"):
            recovery_install.check(self.state)
        pin = self.data / "source/pin.json"
        pin.write_bytes(b"{}")
        with self.assertRaisesRegex(Denied, "RECOVERY_SOURCE_CHANGED"):
            recovery_install.check(self.state)
