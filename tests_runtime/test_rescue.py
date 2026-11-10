import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from nacl.secret import SecretBox

from hostorbit.admission import Admission
from hostorbit.auth import AuthService
from hostorbit.database import Store, identifier
from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import parse_manifest
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical, checksum
from hostorbit.runtime.recovery_import import RecoveryTarget
from hostorbit.runtime.rescue import _encrypted_output, prepare_bundle, validate_request, wipe
from hostorbit.runtime.rescue_payload import database, unpack, verify, write_tar
import test_controller_backup as archive_fixture
from fixtures import PASSWORD


class RescueTests(unittest.TestCase):
    def setUp(self):
        fixture = self.fixture = archive_fixture.ControllerBackupTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.root, self.age = fixture.root, fixture.age_path
        self.source = fixture.backup.create(fixture.recipient)
        self.envelope = json.loads(Path(self.source["provenance"]).read_bytes())
        self.anchor = bytes(fixture.authority.key.verify_key)
        self.box = SecretBox(os.urandom(32))
        # Unit-only substitutes for OS/profile prerequisites. Native CI separately
        # exercises systemd-creds and permissions, never a production bypass flag.
        self.enterContext(patch("hostorbit.runtime.rescue.offline_profile", return_value={"profile": "unit-fixture"}))
        self.enterContext(patch("hostorbit.runtime.recovery_import._trusted_path", side_effect=lambda p, **_: Path(p).absolute()))
        self.enterContext(patch("hostorbit.runtime.recovery_import._identity_credential", side_effect=self.wrap))
        def seal(key, path):
            from hostorbit.runtime.storage import new_private_file
            new_private_file(path, self.box.encrypt(key))
        self.enterContext(patch("hostorbit.runtime.recovery_import.seal_credential", side_effect=seal))
        (self.root / "tools/age-keygen").write_bytes((archive_fixture.AGE_DIR / "age-keygen").read_bytes())
        (self.root / "tools/age-keygen").chmod(0o755)
        self.request = self.issue("target")
        self.bundle = self.root / "recovery.age"

    def wrap(self, data=None, *, ciphertext=None):
        return self.box.encrypt(bytes(data)) if data is not None else self.box.decrypt(ciphertext)

    def issue(self, name):
        return RecoveryTarget.issue(self.root / (name + "-state"), self.root / (name + "-data"), checksum(self.envelope),
                                    keygen_path=self.root / "tools/age-keygen", owner=os.geteuid(), age_path=self.age)

    def pack(self, request=None, output=None):
        return prepare_bundle(self.source["ciphertext"], self.envelope, self.anchor, self.fixture.identity,
                              request or self.request, output or self.bundle, age_path=self.age, tool_owner=os.geteuid())

    def accept(self, digest, **kwargs):
        return RecoveryTarget(self.root / "target-state", owner=os.geteuid(), age_path=self.age).accept(
            self.bundle, owner_digest=digest, username="roman", password=PASSWORD, **kwargs)

    def test_production_roundtrip_imports_private_data_with_new_inactive_identity_and_seal(self):
        review = self.pack()
        self.assertEqual(review["status"], "OWNER_REVIEW_REQUIRED")
        result = self.accept(review["bundle_sha256"])
        self.assertEqual(result["status"], "READ_ONLY_RECOVERY")
        self.assertFalse(result["services_installed"])
        self.assertFalse(result["restore_verified"])
        target = self.root / "target-data"
        admission = Admission(target / "writer-admission", owner=os.geteuid())
        store = Store(target / "app/controller.sqlite3", writers=admission)
        tokens, _ = AuthService(store).login("roman", PASSWORD, ip="127.0.0.1", correlation="recovery-test")
        self.assertIsInstance(tokens.session, str)
        self.assertNotEqual(store.verify_audit(), review["summary"]["audit_head"])
        for kind in ("business", "dispatch"):
            with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
                with store.write(kind=kind):
                    pass
        with self.assertRaisesRegex(Denied, "RECOVERY_ACTIVATION_REQUIRED"):
            admission.publish("OPEN")
        self.assertEqual(admission.state()["phase"], "READ_ONLY_RECOVERY")
        Coordinator(target / "control-gate/snapshots", admission).recover()
        self.assertEqual(admission.state()["phase"], "READ_ONLY_RECOVERY")
        (target / "writer-admission/state.json").unlink()
        Coordinator(target / "control-gate/snapshots", admission).recover_if_idle()
        self.assertEqual(admission.state()["phase"], "READ_ONLY_RECOVERY")
        with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
            with store.write():
                pass
        authority = Authority(target / "control-gate", Policy([]))
        self.addCleanup(authority.close)
        authority.recover()
        with authority.journal.connect() as db:
            gate = db.execute("SELECT * FROM gate").fetchone()
            self.assertEqual(gate["instance_id"], self.request["target_id"])
            self.assertEqual(gate["activated"], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)
        self.assertNotEqual((target / "gate.pub").read_bytes(), self.anchor)
        self.assertEqual(self.box.decrypt((target / "credentials/broker-dek.cred").read_bytes()), self.fixture.dek)
        self.assertFalse((self.root / "target-state/identity.cred").exists())
        for path in target.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.fixture.dek, path.read_bytes())
                self.assertNotIn(b"AGE-SECRET-KEY-", path.read_bytes())
        with self.assertRaisesRegex(Denied, "RECOVERY_REQUEST_CONSUMED"):
            self.accept(review["bundle_sha256"])

    def test_repackaged_bundle_cannot_exceed_target_limit(self):
        with patch("hostorbit.runtime.rescue.MAX_PAYLOAD", 200):
            with self.assertRaisesRegex(Denied, "RESCUE_CIPHERTEXT_SIZE_UNSUPPORTED"):
                _encrypted_output(self.bundle, self.request["recipient"], {"recovery.json": memoryview(b"fixture")},
                                  age_path=self.age, tool_owner=os.geteuid())
        self.assertFalse(self.bundle.exists())

    def test_exact_independent_digest_rejects_reencrypted_database_and_key_substitution(self):
        review = self.pack()
        target_identity = self.wrap(ciphertext=(self.root / "target-state/identity.cred").read_bytes())
        raw = archive_fixture.decrypt_fixture(target_identity, self.bundle).stdout
        members = unpack(bytearray(raw))
        members["vault/portable-keys.json"] = memoryview(canonical({"v": 1, "type": "hostorbit.portable-keyset",
            "generations": [{"version": 1, "key": "A" * 43 + "="}]}))
        members["controller/app.sqlite3"] = memoryview(b"attacker replaced DB")
        self.bundle.unlink()
        _encrypted_output(self.bundle, self.request["recipient"], members, age_path=self.age, tool_owner=os.geteuid())
        with patch("hostorbit.runtime.recovery_import.decrypt", side_effect=AssertionError("must compare hash first")):
            with self.assertRaisesRegex(Denied, "OWNER_DIGEST_MISMATCH"):
                self.accept(review["bundle_sha256"])
        self.assertFalse(any((self.root / "target-data").iterdir()))

    def test_foreign_target_binding_refused_even_with_correct_bundle_digest(self):
        foreign = self.issue("foreign")
        # Encrypt to this target's recipient but retain the foreign challenge.
        foreign["recipient"] = self.request["recipient"]
        foreign["recipient_fingerprint"] = self.request["recipient_fingerprint"]
        review = self.pack(foreign)
        with self.assertRaisesRegex(Denied, "RECOVERY_BINDING_INVALID"):
            self.accept(review["bundle_sha256"])

    def test_owner_auth_is_separate_and_five_failures_lock_request(self):
        review = self.pack()
        target = RecoveryTarget(self.root / "target-state", owner=os.geteuid(), age_path=self.age)
        for _ in range(5):
            with self.assertRaisesRegex(Denied, "RECOVERY_OWNER_AUTH_REQUIRED"):
                target.accept(self.bundle, owner_digest=review["bundle_sha256"], username="roman", password="wrong")
        with self.assertRaisesRegex(Denied, "RECOVERY_AUTH_LOCKED"):
            self.accept(review["bundle_sha256"])
        self.assertFalse(any((self.root / "target-data").iterdir()))

    def test_expired_monotonic_deadline_or_boot_change_refuses_before_decryption(self):
        review = self.pack()
        target = RecoveryTarget(self.root / "target-state", owner=os.geteuid(), age_path=self.age)
        with target.journal.write() as db:
            db.execute("UPDATE request SET deadline_ns=0")
        with self.assertRaisesRegex(Denied, "RESCUE_REQUEST_EXPIRED"):
            self.accept(review["bundle_sha256"])

    def test_nonempty_target_and_short_space_do_not_consume_or_overwrite(self):
        review = self.pack()
        foreign = self.root / "target-data/foreign"
        foreign.write_text("preserve")
        with self.assertRaisesRegex(Denied, "RECOVERY_TARGET_NOT_EMPTY"):
            self.accept(review["bundle_sha256"])
        self.assertEqual(foreign.read_text(), "preserve")
        foreign.unlink()
        from types import SimpleNamespace
        with patch("shutil.disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(Denied, "RECOVERY_SPACE_INSUFFICIENT"):
                self.accept(review["bundle_sha256"])
        self.assertEqual(self.accept(review["bundle_sha256"])["status"], "READ_ONLY_RECOVERY")

    def test_source_sessions_and_queued_work_do_not_resume_after_import(self):
        from hostorbit.queue import JobQueue
        from fixtures import TARGET
        auth = AuthService(self.fixture.store)
        tokens, _ = auth.login("roman", PASSWORD, ip="127.0.0.1", correlation="source-login")
        queue = JobQueue(self.fixture.store)
        queue.register_resource(TARGET, "a" * 64, 1)
        dispatched = queue.enqueue_probe(auth, tokens.session, tokens.csrf, TARGET, "fixture-dispatched-key-123")
        claim, row = queue.claim(identifier())
        queue.advance(claim, "INTENT_PREPARED", permit={"claims": queue.binding(row)})
        queue.advance(claim, "DISPATCHING")
        # A historical imported snapshot may contain an unfinished unclaimed Job.
        with self.fixture.store.write() as db:
            db.execute("UPDATE jobs SET claimed_by=NULL,claim_nonce=NULL WHERE id=?", (dispatched["id"],))
        job = queue.enqueue_probe(auth, tokens.session, tokens.csrf, TARGET, "fixture-request-key-123")
        for number in range(128):
            queue.enqueue_probe(auth, tokens.session, tokens.csrf, TARGET, f"fixture-batch-key-{number:04d}")
        self.source = self.fixture.backup.create(self.fixture.recipient)
        self.envelope = json.loads(Path(self.source["provenance"]).read_bytes())
        # Refresh only the unit target; no public production request renewal.
        self.request = self.issue("with-queue")
        review = self.pack()
        target = RecoveryTarget(self.root / "with-queue-state", owner=os.geteuid(), age_path=self.age)
        target.accept(self.bundle, owner_digest=review["bundle_sha256"], username="roman", password=PASSWORD)
        store = Store(self.root / "with-queue-data/app/controller.sqlite3")
        with store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT status,permit FROM jobs WHERE id=?", (job["id"],)).fetchone()[:], ("CANCELLED_SAFE", None))
            self.assertEqual(db.execute("SELECT count(*) FROM jobs WHERE status='CANCELLED_SAFE' AND permit IS NULL").fetchone()[0], 129)
            self.assertEqual(db.execute("SELECT enabled FROM resources WHERE id=?", (TARGET,)).fetchone()[0], 0)
        restored_auth = AuthService(store)
        restored_tokens, _ = restored_auth.login("roman", PASSWORD, ip="127.0.0.1", correlation="restored-login")
        timeline = JobQueue(store).timeline(restored_auth, restored_tokens.session, job["id"])
        self.assertEqual([item["status"] for item in timeline["items"]], ["QUEUED", "CANCELLED_SAFE"])
        self.assertEqual(timeline["items"][-1]["reason"], "RESTORE_QUARANTINE")
        uncertain = JobQueue(store).timeline(restored_auth, restored_tokens.session, dispatched["id"])
        self.assertEqual([item["status"] for item in uncertain["items"]],
                         ["QUEUED", "INTENT_PREPARED", "DISPATCHING", "UNKNOWN_OUTCOME"])
        with store.read() as db:
            self.assertEqual(db.execute("SELECT state FROM job_incidents WHERE job_id=?", (dispatched["id"],)).fetchone()[0], "OPEN")
        store.verify_audit()

    def test_failed_or_interrupted_import_is_consumed_fail_closed(self):
        review = self.pack()
        with patch("hostorbit.runtime.recovery_import.import_data", side_effect=OSError("fixture ENOSPC")):
            with self.assertRaises(OSError):
                self.accept(review["bundle_sha256"])
        with self.assertRaisesRegex(Denied, "RECOVERY_REQUEST_CONSUMED"):
            self.accept(review["bundle_sha256"])

    def test_wrong_source_anchor_refuses_before_owner_decryption(self):
        with patch("hostorbit.runtime.rescue.decrypt", side_effect=AssertionError("must verify signature first")):
            with self.assertRaisesRegex(Denied, "ARCHIVE_PROVENANCE_INVALID"):
                prepare_bundle(self.source["ciphertext"], self.envelope, b"x" * 32, self.fixture.identity, self.request,
                               self.bundle, age_path=self.age, tool_owner=os.geteuid())

    def test_offline_profile_failure_occurs_before_identity_processing(self):
        with patch("hostorbit.runtime.rescue.offline_profile", side_effect=Denied("RESCUE_SWAP_ENABLED")):
            with self.assertRaisesRegex(Denied, "RESCUE_SWAP_ENABLED"):
                self.pack()
        self.assertFalse(self.bundle.exists())

    def test_request_expiry_does_not_accept_boolean_or_changed_recipient(self):
        for changes in ({"issued_at": True}, {"expires_at": self.request["issued_at"] - 1},
                        {"recipient_fingerprint": "0" * 64}, {"challenge": "short"}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                validate_request({**self.request, **changes})

    def test_source_recovery_point_has_no_fifteen_minute_freshness_restriction(self):
        with patch("hostorbit.runtime.controller_backup.time.time", return_value=time.time() - 86400):
            source = self.fixture.backup.create(self.fixture.recipient)
        self.source = source
        self.envelope = json.loads(Path(source["provenance"]).read_bytes())
        self.request = self.issue("old-source")
        self.assertGreater(time.time() - self.envelope["claims"]["manifest"]["captured_utc"], 86300)
        self.assertEqual(self.pack()["status"], "OWNER_REVIEW_REQUIRED")

    def test_tar_rejects_duplicate_symlink_extension_and_trailing_data(self):
        for kind in ("duplicate", "symlink", "pax", "trailing"):
            stream = io.BytesIO()
            with tarfile.open(mode="w", fileobj=stream, format=tarfile.PAX_FORMAT if kind == "pax" else tarfile.USTAR_FORMAT) as tar:
                info = tarfile.TarInfo("controller/file")
                info.mode, info.size = 0o600, 1
                if kind == "symlink":
                    info.type, info.size, info.linkname = tarfile.SYMTYPE, 0, "/etc/passwd"
                if kind == "pax":
                    info.pax_headers = {"comment": "untrusted extension"}
                tar.addfile(info, io.BytesIO(b"x"))
                if kind == "duplicate":
                    tar.addfile(info, io.BytesIO(b"x"))
            raw = bytearray(stream.getvalue())
            if kind == "trailing":
                raw[-1] = 1
            with self.subTest(kind=kind), self.assertRaisesRegex(Denied, "RESCUE_TAR_INVALID"):
                unpack(raw)

    def test_missing_or_corrupt_member_and_unknown_key_generation_rejected(self):
        raw = bytearray(archive_fixture.decrypt_fixture(self.fixture.identity, self.source["ciphertext"]).stdout)
        members = unpack(raw)
        members["controller/app.sqlite3"] = memoryview(b"corrupt")
        with self.assertRaisesRegex(Denied, "RESCUE_MEMBER_CHANGED"):
            verify(members, self.envelope["claims"], self.anchor)
        members = unpack(raw)
        keyset = parse_manifest(bytes(members["vault/portable-keys.json"]))
        keyset["generations"][0]["version"] = 2
        members["vault/portable-keys.json"] = memoryview(canonical(keyset))
        with self.assertRaisesRegex(Denied, "RESCUE_KEYSET_INVALID"):
            verify(members, self.envelope["claims"], self.anchor)

    def test_signed_integral_archive_with_extra_sqlite_trigger_is_not_import_compatible(self):
        with self.fixture.store.write() as db:
            db.execute("CREATE TRIGGER unexpected_trigger AFTER DELETE ON sessions BEGIN SELECT 1; END")
        self.source = self.fixture.backup.create(self.fixture.recipient)
        self.envelope = json.loads(Path(self.source["provenance"]).read_bytes())
        self.request = self.issue("drifted-schema")
        with self.assertRaisesRegex(Denied, "RESCUE_SCHEMA_DRIFT"):
            self.pack()
        self.assertFalse(self.bundle.exists())

    def test_historical_schema_one_restores_auth_without_running_a_migration(self):
        from contextlib import closing
        from hostorbit.migrations import historical_schema
        from hostorbit.runtime.storage import new_private_file
        legacy = self.root / "legacy"
        legacy.mkdir(mode=0o700)
        path = legacy / "controller.sqlite3"
        new_private_file(path, b"")
        with closing(sqlite3.connect(path, autocommit=True)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(historical_schema())
        store = Store(path, writers=self.fixture.admission)
        auth = AuthService(store)
        auth.create_owner(auth.issue_bootstrap(), "roman", PASSWORD)
        self.fixture.cfg["database"] = str(path)
        (self.fixture.layout.config / "runtime.json").write_bytes(canonical(self.fixture.cfg))
        self.fixture.backup.store = store
        self.source = self.fixture.backup.create(self.fixture.recipient)
        self.envelope = json.loads(Path(self.source["provenance"]).read_bytes())
        self.request = self.issue("legacy-target")
        review = self.pack()
        target = RecoveryTarget(self.root / "legacy-target-state", owner=os.geteuid(), age_path=self.age)
        target.accept(self.bundle, owner_digest=review["bundle_sha256"], username="roman", password=PASSWORD)
        restored = Store(self.root / "legacy-target-data/app/controller.sqlite3")
        restored.verify_audit()
        AuthService(restored).login("roman", PASSWORD, ip="127.0.0.1", correlation="legacy-recovered")
        with restored.read() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
