import copy
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import signal
import time
import unittest
from unittest.mock import patch

import asyncssh

from hostorbit.admission import Admission
from hostorbit.auth import AuthService
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.runtime.activation import Activation
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.recovery_keys import key_facts
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from fixtures import PASSWORD, ACTOR, TARGET, OTHER, SECRET, WORKER_UID, binding, policy


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.writers = Admission.initialize(self.root / "writers", owner=os.geteuid())
        self.writers.publish("OPEN")
        self.store = Store.initialize(self.root / "app/controller.sqlite3")
        self.store.writers = self.writers
        auth = AuthService(self.store)
        self.actor = auth.create_owner(auth.issue_bootstrap(), "roman", PASSWORD)
        old = policy().targets[TARGET].value
        self.old = Policy([old, {**copy.deepcopy(old), "id": OTHER, "secret_ref": ACTOR + ":v1", "dependencies": []}])
        self.new = Policy([{**copy.deepcopy(old), "secret_ref": SECRET + ":v2", "policy_revision": 2}, self.old.targets[OTHER].value])
        new_private_file(self.root / "targets.json", canonical({"v": 1, "targets": [t.value for t in self.old.targets.values()]}))
        new_private_file(self.root / "credential", os.urandom(32))
        self.vault = Vault.initialize(self.root / "vault", self.root / "credential")
        self.old_key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
        self.new_key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
        self.vault.import_ssh(SECRET, 1, self.old_key, owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.vault.import_ssh(SECRET, 2, self.new_key, owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET, policy_revision=2)
        self.vault.import_ssh(ACTOR, 1, self.old_key, owner_id=ACTOR, worker_uid=WORKER_UID, target=OTHER)
        self.vault.revoke(SECRET + ":v1")
        self.authority = Authority.initialize(self.root / "gate", self.old)
        self.addCleanup(self.authority.close)
        self.instance = identifier()
        with self.authority.journal.write() as db:
            db.execute("UPDATE gate SET activated=0,state='RECOVERY_HOLD',instance_id=?", (self.instance,))
        new_private_file(self.root / "gate/recovery-installation.json", b"{}")
        self.writers.publish("READ_ONLY_RECOVERY")
        Coordinator.initialize(self.root / "gate/snapshots", self.writers)
        self.cfg = {"supervisor_directory": str(self.root / "gate"), "database": str(self.store.path),
            "writer_directory": str(self.writers.directory), "app_uid": os.geteuid(), "app_gid": None,
            "vault_directory": str(self.vault.directory), "targets": str(self.root / "targets.json")}
        self.binding = {"target_id": self.instance, "source_instance": identifier(), "source_backup_hash": "a" * 64,
                        "old_host_key": "SHA256:" + "b" * 43}
        self.actions = []
        self.manager = Activation(self.cfg, self.binding, owner=os.geteuid(),
            inspect_keys=lambda p: key_facts(self.vault, self.old, p, WORKER_UID), manage_services=self.actions.append)
        facts = key_facts(self.vault, self.old, self.new, WORKER_UID)
        self.report = {"v": 1, "type": "hostorbit.manual-isolation", "source_instance": self.binding["source_instance"],
            "target_instance": self.instance, "source_backup_hash": "a" * 64, "dependencies_reviewed": True,
            "isolation": {"method": "power_off", "console": "hypervisor-console/ticket-1", "operator": "fixture-owner",
                "old_host_key": self.binding["old_host_key"], "worker_stopped": True, "scheduler_stopped": True, "autostart_blocked": True,
                "old_permissions_revoked": True, "dangerous_operations_stopped": True,
                "observations": [{"source": "console/status-1", "at_utc": int(time.time()) - 20, "isolated": True},
                                 {"source": "independent-network-check", "at_utc": int(time.time()) - 5, "isolated": True}]},
            "targets": {TARGET: {"reachable": True, "evidence": "manual-target-ledger-and-ssh-check",
                "credentials_rotated": True, "old_key_denied": True, "new_key_verified": True,
                "old_key_sha256": facts[TARGET]["old_key_sha256"], "new_key_sha256": facts[TARGET]["new_key_sha256"],
                "direct_stopped": True, "delegated_terminal": True, "postconditions_verified": True},
                OTHER: {"reachable": False, "evidence": "target-not-reachable-manually-quarantined"}}}

    def prepare(self):
        return self.manager.prepare(self.report, self.new)

    def activate(self, review):
        return self.manager.activate(review["plan_id"], review["confirmation_sha256"], "roman", PASSWORD)

    def test_owner_activation_opens_only_rotated_scope_and_survives_restart(self):
        review = self.prepare()
        self.assertEqual(review["quarantined_targets"], [OTHER])
        result = self.activate(review)
        self.assertEqual(result["status"], "ACTIVE")
        self.assertEqual(self.actions, ["stop", "start"])
        self.assertEqual(self.writers.state()["phase"], "OPEN")
        self.store.verify_audit()
        authority = Authority(self.root / "gate", self.new, writers=self.writers)
        self.addCleanup(authority.close)
        authority.recover()
        permit = authority.admit(binding(self.new, identifier()))
        self.assertEqual(permit["claims"]["target"], TARGET)
        denied = {**binding(self.new, identifier()), "target": OTHER, "scope_digest": self.new.targets[OTHER].scope_digest}
        with self.assertRaisesRegex(Denied, "TARGET_QUARANTINED"):
            authority.admit(denied)
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_ssh(SECRET + ":v1", worker_uid=WORKER_UID, target=TARGET)
        with self.assertRaisesRegex(Denied, "ACTIVATION_PLAN_CONSUMED"):
            self.activate(review)

    def test_false_isolation_wrong_host_and_missing_observations_cannot_prepare(self):
        for name, value in (("worker_stopped", False), ("autostart_blocked", False), ("old_host_key", "SHA256:" + "c" * 43), ("observations", [])):
            report = copy.deepcopy(self.report)
            report["isolation"][name] = value
            with self.subTest(name=name), self.assertRaises(Denied):
                self.manager.prepare(report, self.new)
        self.assertEqual(self.writers.state()["phase"], "READ_ONLY_RECOVERY")

    def test_digest_and_owner_password_are_independent_gates(self):
        review = self.prepare()
        with self.assertRaisesRegex(Denied, "CONFIRMATION_REQUIRED"):
            self.manager.activate(review["plan_id"], "0" * 64, "roman", PASSWORD)
        with self.assertRaisesRegex(Denied, "OWNER_AUTH_REQUIRED"):
            self.manager.activate(review["plan_id"], review["confirmation_sha256"], "roman", "wrong")
        self.assertEqual(self.actions, [])
        self.assertEqual(self.writers.state()["phase"], "READ_ONLY_RECOVERY")

    def test_wrong_fingerprint_same_old_key_or_revoked_replacement_is_not_rotation(self):
        report = copy.deepcopy(self.report)
        report["targets"][TARGET]["new_key_sha256"] = "SHA256:" + "z" * 43
        with self.assertRaisesRegex(Denied, "CREDENTIAL_EVIDENCE_REQUIRED"):
            self.manager.prepare(report, self.new)
        self.vault.import_ssh(SECRET, 3, self.old_key, owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET, policy_revision=2)
        reused = Policy([{**self.new.targets[TARGET].value, "secret_ref": SECRET + ":v3"}, self.old.targets[OTHER].value])
        with self.assertRaisesRegex(Denied, "CREDENTIAL_ROTATION_REQUIRED"):
            self.manager.prepare(self.report, reused)
        self.vault.revoke(SECRET + ":v2")
        with self.assertRaisesRegex(Denied, "CREDENTIAL_ROTATION_REQUIRED"):
            self.prepare()

    def test_metadata_acl_edit_without_matching_aead_is_rejected(self):
        import json
        from hostorbit.runtime.protocol import checksum
        with self.vault.journal.write() as db:
            row = db.execute("SELECT metadata FROM secrets WHERE ref=?", (SECRET + ":v2",)).fetchone()
            metadata = json.loads(row[0])
            metadata["allowed_consumers"].append(WORKER_UID + 1)
            metadata["allowed_consumers_digest"] = checksum(metadata["allowed_consumers"])
            db.execute("UPDATE secrets SET metadata=? WHERE ref=?", (canonical(metadata).decode(), SECRET + ":v2"))
        with self.assertRaisesRegex(Denied, "RECOVERY_VAULT_INVALID"):
            self.prepare()

    def test_dependency_closure_and_delegated_effects_remain_quarantined(self):
        shared = self.new.targets[TARGET].value["dependencies"]
        old = Policy([self.old.targets[TARGET].value, {**self.old.targets[OTHER].value, "dependencies": shared}])
        new = Policy([self.new.targets[TARGET].value, {**self.new.targets[OTHER].value, "dependencies": shared}])
        facts = key_facts(self.vault, old, new, WORKER_UID)
        from hostorbit.runtime.activation import isolation_report
        allowed, quarantined = isolation_report(self.report, self.binding, old, new, facts, [], int(time.time()))
        self.assertEqual(allowed, [])
        self.assertEqual(set(quarantined), {TARGET, OTHER})
        self.report["targets"][TARGET]["delegated_terminal"] = False
        review = self.prepare()
        self.assertEqual(review["allowed_targets"], [])

    def test_epoch_change_and_credential_revocation_invalidate_review(self):
        review = self.prepare()
        with self.authority.journal.write() as db:
            db.execute("UPDATE gate SET epoch=epoch+1")
        with self.assertRaisesRegex(Denied, "BASELINE_CHANGED"):
            self.activate(review)

    def test_interruption_after_app_commit_never_reopens_admission_or_replays(self):
        review = self.prepare()
        self.manager.observe = lambda phase: (_ for _ in ()).throw(OSError("fixture ENOSPC")) if phase == "APP_COMMITTED" else None
        with self.assertRaises(OSError):
            self.activate(review)
        self.assertEqual(self.writers.state()["phase"], "READ_ONLY_RECOVERY")
        Coordinator(self.root / "gate/snapshots", self.writers).recover_if_idle()
        self.assertEqual(self.writers.state()["phase"], "READ_ONLY_RECOVERY")
        with self.assertRaisesRegex(Denied, "PLAN_CONSUMED"):
            self.activate(review)

    def test_missing_or_corrupt_signed_activation_record_recloses_business_writes(self):
        review = self.prepare()
        self.activate(review)
        # Losing one of the independent recovery markers must not reclassify
        # the instance as an ordinary fresh installation and skip signature checks.
        (self.root / "gate/recovery-installation.json").unlink()
        (self.root / "gate/activation.json").write_bytes(b"{}")
        authority = Authority(self.root / "gate", self.new, writers=self.writers)
        self.addCleanup(authority.close)
        with self.assertRaisesRegex(Denied, "RECOVERY_ACTIVATION_INVALID"):
            authority.recover()
        self.assertEqual(self.writers.state()["phase"], "READ_ONLY_RECOVERY")

    def test_sigkill_at_each_durable_prepublication_phase_survives_watchdog(self):
        for phase in ("CONFIRMED", "SERVICES_STOPPED", "POLICY_WRITTEN", "APP_COMMITTED", "GATE_COMMITTED", "AUTHORIZED"):
            fixture = ActivationTests()
            fixture.setUp()
            try:
                review = fixture.prepare()
                def child():
                    fixture.manager.observe = lambda current: os.kill(os.getpid(), signal.SIGKILL) if current == phase else None
                    fixture.activate(review)
                process = multiprocessing.get_context("fork").Process(target=child)
                process.start()
                process.join(10)
                if process.is_alive():
                    process.kill()
                    process.join(3)
                    self.fail("Activation child did not reach the bounded checkpoint")
                with self.subTest(phase=phase):
                    self.assertEqual(process.exitcode, -signal.SIGKILL)
                    self.assertEqual(fixture.writers.state()["phase"], "READ_ONLY_RECOVERY")
                    Coordinator(fixture.root / "gate/snapshots", fixture.writers).recover_if_idle()
                    self.assertEqual(fixture.writers.state()["phase"], "READ_ONLY_RECOVERY")
                    with self.assertRaisesRegex(Denied, "PLAN_CONSUMED"):
                        fixture.activate(review)
            finally:
                fixture.doCleanups()

    def test_owner_lockout_expired_review_and_source_inventory_refuse(self):
        review = self.prepare()
        for _ in range(5):
            with self.assertRaisesRegex(Denied, "OWNER_AUTH_REQUIRED"):
                self.manager.activate(review["plan_id"], review["confirmation_sha256"], "roman", "wrong")
        with self.assertRaisesRegex(Denied, "OWNER_AUTH_LOCKED"):
            self.activate(review)
        with patch("hostorbit.runtime.activation.time.monotonic_ns", return_value=10**30):
            fresh = self.prepare()
        with self.assertRaisesRegex(Denied, "PLAN_EXPIRED"):
            with patch("hostorbit.runtime.activation.time.monotonic_ns", return_value=10**31):
                self.activate(fresh)
        report = copy.deepcopy(self.report)
        del report["targets"][OTHER]
        with self.assertRaisesRegex(Denied, "INVENTORY_INCOMPLETE"):
            self.manager.prepare(report, self.new)
