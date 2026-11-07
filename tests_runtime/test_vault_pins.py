from contextlib import closing
import errno
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from hostorbit.admission import Admission
from hostorbit.database import identifier
from hostorbit.errors import Denied
from hostorbit.runtime.broker import Broker
from hostorbit.runtime.pins import capture_with_systemd, pin_vault
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from fixtures import ACTOR, SECRET, TARGET, WORKER_UID, policy, private_key


class VaultPinTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.admission = Admission.initialize(self.root / "writers", owner=os.geteuid())
        self.admission.publish("OPEN")
        self.key = os.urandom(32)
        credential = self.root / "credential"
        new_private_file(credential, self.key)
        self.vault = Vault.initialize(self.root / "vault", credential)
        self.vault.journal.writers = self.admission
        self.broker = self.root / "broker"
        Broker.initialize(self.broker, policy())
        self.snapshot_id = identifier()

    def import_key(self, version):
        return self.vault.import_ssh(SECRET, version, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)

    def capture(self):
        self.admission.publish("SHORT_BARRIER", self.snapshot_id)
        try:
            with self.admission.exclusive(timeout=3):
                return pin_vault(self.vault, self.broker, self.admission, self.snapshot_id)
        finally:
            self.admission.publish("OPEN")

    @property
    def directory(self):
        return self.broker / "snapshot-pins" / self.snapshot_id

    def test_pin_authenticates_active_and_revoked_objects_without_plaintext_keys(self):
        first, second = self.import_key(1), self.import_key(2)
        self.vault.revoke(first)
        # An orphan ciphertext is not a referenced version and is not exported.
        orphan = self.vault.directory / "objects" / ("a" * 64)
        new_private_file(orphan, b"orphan")
        result = self.capture()
        manifest = json.loads((self.directory / "pin.json").read_bytes())
        self.assertEqual(result["status"], "LOCAL_PIN_ONLY")
        self.assertEqual(result["backup_gate"], "DENIED")
        self.assertFalse(result["portable_keys_exported"])
        self.assertEqual(manifest["key_generations"], [1])
        self.assertEqual(manifest["key_fingerprints"], {"1": hashlib.sha256(self.key).hexdigest()})
        self.assertEqual({r["ref"]: r["state"] for r in manifest["references"]}, {first: "REVOKED", second: "ACTIVE"})
        self.assertEqual(len(manifest["files"]), 4)
        self.assertFalse((self.directory / "objects" / orphan.name).exists())
        for file in manifest["files"]:
            data = (self.directory / file["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), file["sha256"])
            self.assertEqual(len(data), file["size"])
        for path in self.directory.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertNotIn(self.key, path.read_bytes())
                self.assertNotIn(b"-----BEGIN OPENSSH PRIVATE KEY-----", path.read_bytes())
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_ssh(first, worker_uid=WORKER_UID, target=TARGET)

    def test_online_copies_include_committed_wal_and_remain_fixed_after_release(self):
        # Keep source connections open so committed rows remain in live WAL.
        with self.vault.journal.connect() as source, closing(sqlite3.connect(self.broker / "receipts.sqlite3", autocommit=True)) as receipts:
            self.import_key(1)
            receipts.execute("INSERT INTO receipts VALUES(?,?,'SUCCEEDED',?,?)", (identifier(), "b" * 64, "{}", "{}"))
            self.assertGreater(Path(str(self.vault.journal.path) + "-wal").stat().st_size, 0)
            self.capture()
            before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.rglob("*") if p.is_file()}
            self.import_key(2)
            self.vault.revoke(SECRET + ":v1")
            receipts.execute("INSERT INTO receipts VALUES(?,?,'FAILED',?,?)", (identifier(), "c" * 64, "{}", "{}"))
            with closing(sqlite3.connect(self.directory / "vault.sqlite3")) as copied:
                self.assertEqual(copied.execute("SELECT ref,state FROM secrets").fetchall(), [(SECRET + ":v1", "ACTIVE")])
                self.assertEqual(copied.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            with closing(sqlite3.connect(self.directory / "receipts.sqlite3")) as copied:
                self.assertEqual(copied.execute("SELECT state FROM receipts").fetchall(), [("SUCCEEDED",)])
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.rglob("*") if p.is_file()})

    def test_empty_vault_still_pins_its_working_key_generation(self):
        self.capture()
        manifest = json.loads((self.directory / "pin.json").read_bytes())
        self.assertEqual(manifest["references"], [])
        self.assertEqual(manifest["key_generations"], [1])
        self.assertEqual(len(manifest["files"]), 2)

    def test_root_latch_without_exclusive_lock_or_another_snapshot_is_rejected(self):
        self.admission.publish("SHORT_BARRIER", self.snapshot_id)
        with self.assertRaisesRegex(Denied, "SNAPSHOT_EXCLUSION_REQUIRED"):
            pin_vault(self.vault, self.broker, self.admission, self.snapshot_id)
        with self.admission.exclusive(timeout=1):
            with self.assertRaisesRegex(Denied, "SNAPSHOT_BINDING_INVALID"):
                pin_vault(self.vault, self.broker, self.admission, identifier())
        self.assertFalse((self.broker / "snapshot-pins").exists())

    def test_existing_pin_is_never_overwritten_or_reused(self):
        self.import_key(1)
        self.capture()
        before = (self.directory / "pin.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual((self.directory / "pin.json").read_bytes(), before)

    def test_unknown_key_generation_and_aad_or_ciphertext_substitution_have_no_complete_marker(self):
        reference = self.import_key(1)
        with self.vault.journal.connect() as db:
            row = db.execute("SELECT * FROM secrets").fetchone()
        for damage in ("generation", "aad", "object"):
            with self.subTest(damage=damage):
                self.snapshot_id = identifier()
                metadata = json.loads(row["metadata"])
                if damage == "generation":
                    metadata["key_version"] = 2
                if damage == "aad":
                    metadata["owner_id"] = TARGET
                with self.vault.journal.write() as db:
                    db.execute("UPDATE secrets SET metadata=? WHERE ref=?", (canonical(metadata).decode(), reference))
                if damage == "object":
                    (self.vault.directory / "objects" / row["object_digest"]).write_bytes(b"damaged ciphertext")
                with self.assertRaisesRegex(Denied, "VAULT_PIN_KEY_GENERATION_UNSUPPORTED|VAULT_PIN_OBJECT_CORRUPT"):
                    self.capture()
                self.assertFalse((self.directory / "pin.json").exists())

    def test_disk_full_or_lost_barrier_cannot_finish_a_pin(self):
        self.import_key(1)
        original = new_private_file
        def fail_object(path, data):
            if Path(path).parent.name == "objects":
                raise OSError(errno.ENOSPC, "fixture full disk")
            return original(path, data)
        with patch("hostorbit.runtime.pins.new_private_file", side_effect=fail_object):
            with self.assertRaises(OSError):
                self.capture()
        self.assertFalse((self.directory / "pin.json").exists())
        self.snapshot_id = identifier()
        def lose_barrier(path, data):
            result = original(path, data)
            if Path(path).name == "receipts.sqlite3":
                self.admission.publish("OPEN")
            return result
        with patch("hostorbit.runtime.pins.new_private_file", side_effect=lose_barrier):
            with self.assertRaisesRegex(Denied, "SNAPSHOT_BINDING_INVALID"):
                self.capture()
        self.assertFalse((self.directory / "pin.json").exists())

    def test_space_preflight_fails_before_creating_pin_namespace(self):
        with patch("hostorbit.runtime.pins.shutil.disk_usage", return_value=type("Space", (), {"free": 1})()):
            with self.assertRaisesRegex(Denied, "VAULT_PIN_SPACE_INSUFFICIENT"):
                self.capture()
        self.assertFalse((self.broker / "snapshot-pins").exists())

    def test_unprivileged_caller_cannot_start_the_native_credential_helper(self):
        with patch("hostorbit.runtime.pins.os.geteuid", return_value=12345), patch("hostorbit.runtime.pins.subprocess.run") as run:
            with self.assertRaisesRegex(Denied, "LOCAL_ROOT_REQUIRED"):
                capture_with_systemd(self.snapshot_id)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
