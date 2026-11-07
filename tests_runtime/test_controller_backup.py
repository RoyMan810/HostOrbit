import base64
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest

from nacl.secret import Aead
from nacl.signing import SigningKey

from hostorbit.admission import Admission
from hostorbit.auth import AuthService
from hostorbit.database import Store
from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import CONTROLLER_FILES, feed, seal
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.broker import Broker
from hostorbit.runtime.controller_backup import ControllerBackup, Layout, verify_provenance
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.pins import pin_vault
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from hostorbit.migrations import historical_schema
from fixtures import ACTOR, PASSWORD, SECRET, TARGET, WORKER_UID, private_key


AGE_DIR = Path(os.environ.get("HOSTORBIT_TEST_AGE_DIR", str(Path(__file__).resolve().parents[2] / ".hostorbit-tools/age")))


def fixture_identity():
    result = subprocess.run([str(AGE_DIR / "age-keygen")], capture_output=True, check=True)
    public = subprocess.run([str(AGE_DIR / "age-keygen"), "-y"], input=result.stdout, capture_output=True, check=True).stdout.decode().strip()
    return result.stdout, public


def decrypt_fixture(identity, ciphertext):
    read, write = os.pipe()
    try:
        os.write(write, identity)
        os.close(write)
        write = None
        return subprocess.run([str(AGE_DIR / "age"), "--decrypt", "--identity", f"/dev/fd/{read}", str(ciphertext)],
                              pass_fds=(read,), capture_output=True, timeout=10)
    finally:
        os.close(read)
        if write is not None:
            os.close(write)


class ControllerBackupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "tools").mkdir(mode=0o700)
        self.age_path = self.root / "tools/age"
        self.age_path.write_bytes((AGE_DIR / "age").read_bytes())
        self.age_path.chmod(0o755)
        self.admission = Admission.initialize(self.root / "writers", owner=os.geteuid())
        self.store = Store.initialize(self.root / "app-data/controller.sqlite3")
        self.authority = Authority.initialize(self.root / "gate", Policy([]))
        self.addCleanup(self.authority.close)
        self.coordinator = Coordinator.initialize(self.root / "gate/snapshots", self.admission)
        self.store.writers = self.admission
        auth = AuthService(self.store)
        self.owner = auth.create_owner(auth.issue_bootstrap(), "roman", PASSWORD)
        self.dek = os.urandom(32)
        new_private_file(self.root / "credential", self.dek)
        self.vault = Vault.initialize(self.root / "vault", self.root / "credential")
        self.broker = self.root / "broker"
        Broker.initialize(self.broker, Policy([]))
        for version in (1, 2):
            ref = self.vault.import_ssh(SECRET, version, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
            if version == 1:
                self.vault.revoke(ref)
        self.layout = Layout(self.root / "installed", self.root / "config")
        (self.layout.app / "bundle").mkdir(parents=True)
        self.layout.config.mkdir()
        self.cfg = {"writer_directory": str(self.admission.directory), "database": str(self.store.path),
                    "app_uid": os.geteuid(), "broker_uid": os.geteuid(), "broker_directory": str(self.broker),
                    "supervisor_directory": str(self.authority.directory), "targets": str(self.layout.config / "targets.json"),
                    "public_verify_key": str(self.layout.config / "gate.pub"), "vault_directory": str(self.vault.directory)}
        for path, content in {
            self.layout.config / "runtime.json": canonical(self.cfg), self.layout.config / "targets.json": canonical({"v": 1, "targets": []}),
            self.layout.config / "gate.pub": bytes(self.authority.key.verify_key), self.layout.config / "compose.json": b"{}",
            self.layout.config / "release-trust.pub": bytes(SigningKey.generate().verify_key),
            self.layout.app / "installation.json": canonical({"source_commit": "a" * 40}),
            self.layout.app / "bundle/manifest.json": canonical({"source_commit": "a" * 40}),
            self.layout.app / "bundle/manifest.sig": b"s" * 64,
            self.layout.app / "bundle/requirements-install.txt": b"fixture==1 --hash=sha256:fixture\n",
            self.layout.app / "bundle/sbom.cdx.json": b"{}",
        }.items():
            new_private_file(path, content)
        self.identity, self.recipient = fixture_identity()

        def pin(snapshot_id):
            return pin_vault(self.vault, self.broker, self.admission, snapshot_id)

        def sealer(config, directory, manifest, public_recipient, ciphertext):
            self.assertEqual(self.admission.state()["phase"], "OPEN")
            # This commit belongs to a later audit sequence. It must be possible
            # while encryption runs and must not enter the already pinned DB.
            with self.store.write() as db:
                self.store.event(db, at=1, actor="fixture", kind="after.barrier", target="controller", outcome="SUCCEEDED", correlation="fixture")
            data = io.BytesIO()
            feed(directory, manifest, public_recipient, data, owner=os.geteuid())
            data.seek(0)
            new_private_file(ciphertext, b"")
            with Path(ciphertext).open("wb") as output:
                seal(self.vault, self.broker, manifest["snapshot_id"], data, output,
                     age_path=self.age_path, age_owner=os.geteuid())

        self.backup = ControllerBackup(self.cfg, layout=self.layout, owner=os.geteuid(), pin=pin, sealer=sealer)

    def test_signed_archive_decrypts_with_portable_dek_and_exact_pinned_state(self):
        before = self.store.verify_audit()
        result = self.backup.create(self.recipient)
        self.assertEqual(result["status"], "LOCAL_SIGNED_ONLY")
        self.assertTrue(result["portable_keys_exported"])
        self.assertFalse(result["off_host"])
        self.assertFalse(result["restore_verified"])
        self.assertEqual(result["backup_gate"], "DENIED")
        envelope = json.loads(Path(result["provenance"]).read_bytes())
        claims = verify_provenance(Path(result["ciphertext"]), envelope, bytes(self.authority.key.verify_key))
        self.assertEqual(claims["manifest"]["audit_head"], before)
        self.assertNotEqual(self.store.verify_audit(), before)
        decrypted = decrypt_fixture(self.identity, result["ciphertext"])
        self.assertEqual(decrypted.returncode, 0)
        with tarfile.open(fileobj=io.BytesIO(decrypted.stdout)) as tar:
            names = set(tar.getnames())
            self.assertTrue({"controller/" + name for name in CONTROLLER_FILES}.issubset(names))
            self.assertTrue(all(info.isfile() and info.mode == 0o600 for info in tar.getmembers()))
            self.assertFalse(any("signing.key" in name or "broker-dek" in name for name in names))
            keyset = json.load(tar.extractfile("vault/portable-keys.json"))
            self.assertEqual(keyset["generations"], [{"version": 1, "key": base64.b64encode(self.dek).decode()}])
            pin = json.load(tar.extractfile("vault/pin.json"))
            for record in claims["manifest"]["files"]:
                payload = tar.extractfile("controller/" + record["path"]).read()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), record["sha256"])
            for record in pin["files"]:
                payload = tar.extractfile("vault/" + record["path"]).read()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), record["sha256"])
            dbfile = self.root / "fixture-decrypted.sqlite3"
            new_private_file(dbfile, tar.extractfile("controller/app.sqlite3").read())
            with closing(sqlite3.connect(dbfile)) as db:
                db.row_factory = sqlite3.Row
                self.assertEqual(Store.verify_audit_connection(db), before)
                db.row_factory = None
                self.assertEqual(db.execute("SELECT id,username FROM users").fetchall(), [(self.owner, "roman")])
            for ref in pin["references"]:
                ciphertext = tar.extractfile("vault/objects/" + ref["object_digest"]).read()
                metadata_db = self.root / "fixture-vault.sqlite3"
                if not metadata_db.exists():
                    new_private_file(metadata_db, tar.extractfile("vault/vault.sqlite3").read())
                with closing(sqlite3.connect(metadata_db)) as db:
                    raw, state = db.execute("SELECT metadata,state FROM secrets WHERE ref=?", (ref["ref"],)).fetchone()
                self.assertEqual(state, ref["state"])
                self.assertEqual(Aead(self.dek).decrypt(ciphertext, canonical(json.loads(raw))), private_key())
        for path in Path(result["ciphertext"]).parent.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.dek, path.read_bytes())
                self.assertNotIn(b"AGE-SECRET-KEY-", path.read_bytes())
        with self.coordinator.journal.connect() as db:
            self.assertEqual([r["phase"] for r in db.execute("SELECT phase FROM transitions")][-3:], ["BARRIER_RELEASED", "SEALED", "SIGNED"])

    def test_wrong_anchor_ciphertext_or_recipient_cannot_verify_or_decrypt(self):
        result = self.backup.create(self.recipient)
        envelope = json.loads(Path(result["provenance"]).read_bytes())
        cipher = Path(result["ciphertext"])
        with self.assertRaisesRegex(Denied, "ARCHIVE_PROVENANCE_INVALID"):
            verify_provenance(cipher, envelope, bytes(SigningKey.generate().verify_key))
        wrong, _ = fixture_identity()
        self.assertNotEqual(decrypt_fixture(wrong, cipher).returncode, 0)
        payload = bytearray(cipher.read_bytes())
        payload[-1] ^= 1
        cipher.write_bytes(payload)
        with self.assertRaisesRegex(Denied, "ARCHIVE_CIPHERTEXT_CHANGED"):
            verify_provenance(cipher, envelope, bytes(self.authority.key.verify_key))

    def test_sealer_failure_is_durable_failed_without_blocking_business_writes(self):
        def failed(*_):
            raise OSError("fixture ENOSPC")
        self.backup.sealer = failed
        with self.assertRaises(OSError):
            self.backup.create(self.recipient)
        with self.coordinator.journal.connect() as db:
            self.assertEqual(db.execute("SELECT phase FROM transitions ORDER BY seq DESC LIMIT 1").fetchone()[0], "FAILED")
        self.assertEqual(self.admission.state()["phase"], "OPEN")
        self.assertFalse(list(self.coordinator.directory.glob("captures/*/provenance.json")))

    def test_changed_pin_or_working_dek_refuses_portable_export(self):
        original = self.backup.sealer
        def changed(config, directory, manifest, public_recipient, ciphertext):
            self.vault._aead = Aead(os.urandom(32))
            original(config, directory, manifest, public_recipient, ciphertext)
        self.backup.sealer = changed
        with self.assertRaisesRegex(Denied, "ARCHIVE_KEYSET_UNAVAILABLE"):
            self.backup.create(self.recipient)
        self.assertFalse(list(self.coordinator.directory.glob("captures/*/provenance.json")))

    def test_source_digest_or_scope_change_cannot_be_signed(self):
        original = self.backup.sealer
        def changed(config, directory, manifest, public_recipient, ciphertext):
            (directory / "targets.json").write_bytes(b'{}')
            original(config, directory, manifest, public_recipient, ciphertext)
        self.backup.sealer = changed
        with self.assertRaisesRegex(Denied, "ARCHIVE_SOURCE_CHANGED"):
            self.backup.create(self.recipient)
        self.assertFalse(list(self.coordinator.directory.glob("captures/*/provenance.json")))

    def test_historical_schema_one_is_backed_up_without_migrating_the_live_database(self):
        legacy = self.root / "legacy"
        legacy.mkdir(mode=0o700)
        database = legacy / "controller.sqlite3"
        new_private_file(database, b"")
        with closing(sqlite3.connect(database, autocommit=True)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(historical_schema())
        store = Store(database, writers=self.admission)
        auth = AuthService(store)
        owner = auth.create_owner(auth.issue_bootstrap(), "legacy-owner", PASSWORD)
        self.cfg["database"] = str(database)
        (self.layout.config / "runtime.json").write_bytes(canonical(self.cfg))
        self.backup.store = store
        result = self.backup.create(self.recipient)
        self.assertEqual(json.loads(Path(result["provenance"]).read_bytes())["claims"]["manifest"]["schema"], 1)
        with store.read() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT id FROM users").fetchone()[0], owner)

    def test_stream_rejects_path_expansion_and_truncation_without_signed_completion(self):
        def invalid(config, directory, manifest, public_recipient, ciphertext):
            manifest["files"][0]["path"] = "../credential"
            feed(directory, manifest, public_recipient, io.BytesIO(), owner=os.geteuid())
        self.backup.sealer = invalid
        with self.assertRaisesRegex(Denied, "ARCHIVE_MANIFEST_INVALID"):
            self.backup.create(self.recipient)
        self.assertFalse(list(self.coordinator.directory.glob("captures/*/provenance.json")))

    def test_interrupted_stream_never_produces_a_signature(self):
        def truncated(config, directory, manifest, public_recipient, ciphertext):
            data = io.BytesIO()
            feed(directory, manifest, public_recipient, data, owner=os.geteuid())
            data = io.BytesIO(data.getvalue()[:-100])
            new_private_file(ciphertext, b"")
            with Path(ciphertext).open("wb") as output:
                seal(self.vault, self.broker, manifest["snapshot_id"], data, output,
                     age_path=self.age_path, age_owner=os.geteuid())
        self.backup.sealer = truncated
        with self.assertRaises(OSError):
            self.backup.create(self.recipient)
        self.assertFalse(list(self.coordinator.directory.glob("captures/*/provenance.json")))


if __name__ == "__main__":
    unittest.main()
