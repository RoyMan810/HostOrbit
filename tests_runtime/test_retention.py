import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import itertools
import json
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from nacl.signing import SigningKey

from vpn_orbit.errors import Denied
from vpn_orbit.runtime import backup_cli
from vpn_orbit.runtime.controller_backup import sign_provenance
from vpn_orbit.runtime.protocol import canonical, checksum
from vpn_orbit.runtime.retention import Retention
from vpn_orbit.runtime.storage import new_private_file
from test_migration_backup import PublicationFixture


class RetentionTests(PublicationFixture, TestCase):
    def setUp(self):
        super().setUp()
        root = self.target.parent
        self.config.update(broker_uid=os.geteuid(), broker_directory=str(root / "broker"))
        self.owner_key = SigningKey.generate()
        self.anchor = root / "owner.pub"
        self.evidence = root / "restore-report"
        new_private_file(self.evidence, b"operator record of isolated restore and independent storage")
        new_private_file(self.anchor, bytes(self.owner_key.verify_key))
        self.approval = root / "approval"
        self.retention = Retention(self.config, owner=os.geteuid(), owner_key=self.anchor,
                                   target_path=self.target, runner=self.publisher.runner)
        self.old = self.capture
        self.references = [{"ref": "fixture:v1", "key_generation": 1, "state": "ACTIVE",
                            "object_digest": "a" * 64, "metadata_sha256": "b" * 64}]
        self.bind_pin(self.snapshot, self.references)
        self.publisher.publish(self.snapshot)
        self.keep = self.new_snapshot()

    def bind_pin(self, snapshot, references):
        pin = {"v": 1, "type": "vault.pin", "snapshot_id": snapshot, "key_generations": [1],
               "key_fingerprints": {"1": "d" * 64}, "references": references, "files": []}
        directory = Path(self.config["broker_directory"]) / "snapshot-pins" / snapshot
        directory.mkdir(parents=True, mode=0o700)
        new_private_file(directory / "pin.json", canonical(pin))
        self.manifest["pin_sha256"] = checksum(pin)
        envelope = sign_provenance(self.manifest, "age1" + "q" * 58, self.capture / "controller.age", self.signing_key)
        (self.capture / "provenance.json").write_bytes(canonical(envelope))

    def publish_keep(self, refs=None):
        self.bind_pin(self.keep, self.references if refs is None else refs)
        self.publisher.publish(self.keep)

    def cli(self, command, *args, success=True):
        output, errors = io.StringIO(), io.StringIO()
        with (patch("vpn_orbit.runtime.cli.configuration", return_value=self.config),
              patch("vpn_orbit.runtime.retention.Retention", return_value=self.retention),
              patch("os.geteuid", side_effect=itertools.chain([0], itertools.repeat(os.geteuid()))), redirect_stdout(output), redirect_stderr(errors)):
            code = backup_cli.main([command, *map(str, args)])
        self.assertEqual(code, 0 if success else 1, errors.getvalue())
        return json.loads(output.getvalue()) if success else errors.getvalue().strip()

    def issue_approval(self):
        args = ["--snapshot-id", self.snapshot, "--keep-id", self.keep, "--evidence", self.evidence]
        claims = self.cli("retention-review", *args)
        signature = self.owner_key.sign(canonical(claims)).signature
        new_private_file(self.approval, canonical({"claims": claims, "signature": base64.b64encode(signature).decode()}))
        return [*args, "--approval", self.approval]

    def test_manual_retirement_preserves_both_external_copies_and_dependencies(self):
        self.publish_keep()
        ops, files = list(self.remote.ops), dict(self.remote.files)
        args = self.issue_approval()
        for _ in range(2):
            self.assertEqual(self.cli("retire-local", *args)["status"], "LOCAL_CIPHERTEXT_RETIRED")
        self.assertFalse((self.old / "controller.age").exists())
        self.assertTrue((self.capture / "controller.age").exists())
        self.assertTrue((self.old / "publication-receipt.json").exists())
        self.assertEqual((self.remote.ops, self.remote.files), (ops, files))
        inventory = self.cli("retention-inventory")["controller"]
        self.assertEqual({x["snapshot_id"]: x["local_ciphertext_present"] for x in inventory},
                         {self.snapshot: False, self.keep: True})

    def test_missing_replacement_or_changed_remote_member_never_recreates_or_releases(self):
        self.publish_keep()
        args = self.issue_approval()
        ops = list(self.remote.ops)
        remote = "/store/" + self.keep
        self.remote.dirs.remove(remote)
        self.assertEqual(self.cli("retire-local", *args, success=False), "SFTP_FINAL_INCOMPLETE")
        self.remote.dirs.add(remote)
        self.remote.files[remote + "/COMPLETE"] = b"corrupted"
        self.assertEqual(self.cli("retire-local", *args, success=False), "SFTP_READBACK_MISMATCH")
        self.assertTrue((self.old / "controller.age").exists())
        self.assertEqual(self.remote.ops, ops)

    def test_retirement_requires_distinct_copy_complete_dependencies_and_bound_evidence(self):
        self.publish_keep([])
        with self.assertRaisesRegex(Denied, "RETENTION_LAST_COPY_PROTECTED"):
            self.retention.review(self.snapshot, self.snapshot, self.evidence)
        with self.assertRaisesRegex(Denied, "RETENTION_VAULT_DEPENDENCY_PROTECTED"):
            self.retention.review(self.snapshot, self.keep, self.evidence)
        self.assertTrue((self.old / "controller.age").exists())

    def test_evidence_substitution_and_wrong_owner_key_fail_closed(self):
        self.publish_keep()
        args = self.issue_approval()
        before = self.evidence.read_bytes()
        self.evidence.write_bytes(b"substituted")
        self.assertEqual(self.cli("retire-local", *args, success=False), "RETENTION_APPROVAL_INVALID")
        self.evidence.write_bytes(before)
        self.anchor.write_bytes(bytes(SigningKey.generate().verify_key))
        self.assertEqual(self.cli("retire-local", *args, success=False), "RETENTION_APPROVAL_INVALID")
        self.assertTrue((self.old / "controller.age").exists())

    def test_missing_pin_and_invalid_audit_head_protect_local_copy(self):
        self.manifest["audit_head"] = "e" * 64
        self.publish_keep()
        with self.assertRaisesRegex(Denied, "RETENTION_AUDIT_CHECKPOINT_PROTECTED"):
            self.retention.review(self.snapshot, self.keep, self.evidence)
        pin = Path(self.config["broker_directory"]) / "snapshot-pins" / self.keep / "pin.json"
        pin.write_bytes(b"{}")
        with self.assertRaisesRegex(Denied, "RETENTION_PIN_CHANGED"):
            self.retention.review(self.snapshot, self.keep, self.evidence)
        self.assertTrue((self.old / "controller.age").exists())

    def test_broker_readback_uses_only_bound_header(self):
        from vpn_orbit.runtime.publication import _feed, receive_and_publish
        from vpn_orbit.runtime.backup_target import BackupTarget
        self.publish_keep()
        target = BackupTarget.load(self.target, owner=os.geteuid())
        envelope = json.loads((self.capture / "provenance.json").read_bytes())
        wire = io.BytesIO()
        _feed(self.capture, self.keep, target, envelope, wire, os.geteuid(), verify_only=True)
        # Root owns the public key on installed systems. Map the verifier to the fixture owner.
        from vpn_orbit.runtime.storage import protected_bytes
        def protected(path, *, owner, maximum):
            return protected_bytes(path, owner=os.geteuid(), maximum=maximum)
        with (patch.object(BackupTarget, "load", return_value=target),
              patch("vpn_orbit.runtime.publication.protected_bytes", side_effect=protected),
              patch("vpn_orbit.runtime.publication._transfer") as transfer):
            wire.seek(0)
            receive_and_publish(self.config, self.keep, wire, verify_only=True)
            transfer.assert_called_once_with(self.config, target, self.keep, None, envelope["claims"], envelope,
                                             verify_only=True)
            with self.assertRaisesRegex(Denied, "PUBLICATION_BINDING_INVALID"):
                receive_and_publish(self.config, self.keep, io.BytesIO(wire.getvalue() + b"x"), verify_only=True)
