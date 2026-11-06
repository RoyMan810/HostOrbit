from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from stage0.recovery import (
    Rejected,
    Snapshot,
    accept_bundle,
    issue_request,
    prepare_bundle,
    seal_source,
)


def age_command(*args, data=b""):
    return subprocess.run(
        args, input=data, capture_output=True, check=True, timeout=15
    ).stdout


def database_with(value):
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE fixture (name TEXT NOT NULL)")
        db.execute("INSERT INTO fixture VALUES (?)", (value,))
        return db.serialize()


def pack(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.offline_identity = self.path / "offline.agekey"
        self.transport_identity = self.path / "target.agekey"
        for identity in (self.offline_identity, self.transport_identity):
            age_command("age-keygen", "-o", str(identity))
        owner_recipient = age_command("age-keygen", "-y", str(self.offline_identity)).decode().strip()
        self.signing_key = SigningKey.generate()
        self.snapshot = Snapshot(database_with("original"), secrets.token_bytes(64))
        self.backup = seal_source(self.snapshot, owner_recipient, self.signing_key)
        self.ledger = self.path / "target.sqlite3"
        self.request = self.issue()

    def issue(self, *, ledger=None, target_id="target", identity=None):
        return issue_request(
            self.ledger if ledger is None else ledger,
            target_id=target_id,
            transport_identity=self.transport_identity if identity is None else identity,
            source_envelope_sha256=self.backup.envelope_sha256,
        )

    def prepare(self, *, backup=None, request=None, signer=None):
        return prepare_bundle(
            self.backup if backup is None else backup,
            self.signing_key.verify_key if signer is None else signer,
            self.offline_identity,
            self.request if request is None else request,
        )

    def accept(self, bundle, digest, *, ledger=None, identity=None):
        return accept_bundle(
            self.ledger if ledger is None else ledger,
            self.transport_identity if identity is None else identity,
            bundle, owner_digest=digest,
        )

    def substitute(self, bundle, snapshot):
        plaintext = age_command("age", "-d", "-i", str(self.transport_identity), data=bundle)
        payload = json.loads(plaintext)
        payload["snapshot"] = snapshot.encoded()
        return age_command("age", "-r", self.request.recipient, data=pack(payload))

    def test_verified_backup_is_transferred_and_consumed_once(self):
        bundle, review = self.prepare()
        self.assertEqual(review.manifest, self.snapshot.manifest())
        self.assertEqual(review.bundle_sha256, hashlib.sha256(bundle).hexdigest())
        self.assertEqual(review.request, self.request)
        with self.assertRaises(subprocess.CalledProcessError):
            age_command("age", "-d", "-i", str(self.offline_identity), data=bundle)
        self.offline_identity.unlink()

        restored = self.accept(bundle, review.bundle_sha256)
        self.assertEqual(restored, self.snapshot)
        with closing(sqlite3.connect(":memory:")) as db:
            db.deserialize(restored.database)
            self.assertEqual(db.execute("SELECT name FROM fixture").fetchone(), ("original",))
        with self.assertRaisesRegex(Rejected, "^REQUEST_CONSUMED$"):
            self.accept(bundle, review.bundle_sha256)
        with self.assertRaises(FileExistsError):
            self.issue()

    def test_substituted_db_or_deks_with_correct_binding_are_rejected_before_decrypt(self):
        bundle, review = self.prepare()
        substitutes = (
            replace(self.snapshot, database=database_with("changed")),
            replace(self.snapshot, deks=secrets.token_bytes(64)),
        )
        for candidate in substitutes:
            replacement = self.substitute(bundle, candidate)
            with patch("stage0.recovery._run_age") as run_age:
                with self.assertRaisesRegex(Rejected, "^OWNER_DIGEST_MISMATCH$"):
                    self.accept(replacement, review.bundle_sha256)
                run_age.assert_not_called()
        self.assertEqual(self.accept(bundle, review.bundle_sha256), self.snapshot)

    def test_missing_or_partial_owner_digest_is_rejected(self):
        bundle, review = self.prepare()
        for digest in ("", review.bundle_sha256[:16]):
            with self.subTest(digest=digest), self.assertRaisesRegex(Rejected, "^OWNER_DIGEST_REQUIRED$"):
                self.accept(bundle, digest)

    def test_wrong_signer_and_modified_source_are_denied_before_decrypt(self):
        with patch("stage0.recovery._decrypt") as decrypt:
            with self.assertRaisesRegex(Rejected, "^SOURCE_SIGNATURE$"):
                self.prepare(signer=SigningKey.generate().verify_key)
            tampered = replace(self.backup, ciphertext=self.backup.ciphertext + b"modified")
            with self.assertRaisesRegex(Rejected, "^SOURCE_CIPHERTEXT$"):
                self.prepare(backup=tampered)
            decrypt.assert_not_called()

    def test_signed_manifest_must_match_decrypted_snapshot(self):
        data = json.loads(self.backup.envelope)
        data["manifest"]["deks"]["size"] += 1
        envelope = pack(data)
        backup = replace(
            self.backup, envelope=envelope, signature=self.signing_key.sign(envelope).signature,
        )
        request = replace(self.request, source_envelope_sha256=backup.envelope_sha256)
        with self.assertRaisesRegex(Rejected, "^SOURCE_MANIFEST$"):
            self.prepare(backup=backup, request=request)

    def test_another_challenge_target_or_source_is_rejected_even_with_confirmed_digest(self):
        for field, wrong in (
            ("challenge", secrets.token_hex(32)),
            ("target_id", "other-target"),
            ("source_envelope_sha256", secrets.token_hex(32)),
            ("expires_at", self.request.expires_at + 1),
        ):
            with self.subTest(field=field):
                request = replace(self.request, **{field: wrong})
                bundle, _ = self.prepare()
                plaintext = age_command("age", "-d", "-i", str(self.transport_identity), data=bundle)
                payload = json.loads(plaintext)
                payload["binding"] = request.binding()
                candidate = age_command("age", "-r", request.recipient, data=pack(payload))
                with self.assertRaisesRegex(Rejected, "^WRONG_BINDING$"):
                    self.accept(candidate, hashlib.sha256(candidate).hexdigest())

    def test_wrong_target_transport_key_is_rejected(self):
        bundle, review = self.prepare()
        with self.assertRaisesRegex(Rejected, "^WRONG_RECIPIENT$"):
            self.accept(bundle, review.bundle_sha256, identity=self.offline_identity)

    def test_bundle_expiring_during_decryption_does_not_consume_challenge(self):
        bundle, review = self.prepare()
        with patch("stage0.recovery._now", side_effect=[self.request.expires_at - 1, self.request.expires_at]):
            with self.assertRaisesRegex(Rejected, "^REQUEST_EXPIRED$"):
                self.accept(bundle, review.bundle_sha256)
        self.assertEqual(self.accept(bundle, review.bundle_sha256), self.snapshot)

    def test_concurrent_acceptance_grants_one_import(self):
        bundle, review = self.prepare()
        barrier = Barrier(2, timeout=15)

        def attempt():
            barrier.wait()
            try:
                return self.accept(bundle, review.bundle_sha256)
            except Rejected as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as executor:
            attempts = [executor.submit(attempt) for _ in range(2)]
            self.assertCountEqual(
                [future.result(timeout=20) for future in attempts],
                [self.snapshot, "REQUEST_CONSUMED"],
            )
