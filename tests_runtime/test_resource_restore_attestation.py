import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import AGE_SHA256
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.rescue import _encrypted_output
from hostorbit.runtime.resource_restore_attestation import verify_attestation, verify_restore_source
from test_controller_backup import AGE_DIR


NOW = 1_800_000_000
DAY = 86400
PROCEDURE = "a" * 64
EVIDENCE = b'{"fixture":"operator test record"}'


class RestoreAttestationTests(unittest.TestCase):
    def setUp(self):
        self.signer = SigningKey.generate()
        self.claims = {
            "v": 1,
            "type": "hostorbit.resource-restore-attestation",
            "resource_type": "docker.named-volume",
            "application_schema": "fixture-v1",
            "procedure_sha256": PROCEDURE,
            "tested_at": NOW - DAY,
            "test_archive_sha256": "b" * 64,
            "evidence_sha256": hashlib.sha256(EVIDENCE).hexdigest(),
            "checks": {"new_empty_target": True, "data_and_metadata": True,
                       "application_check": True, "occupied_target_refused": True},
        }

    def envelope(self, *, signer=None):
        signature = (signer or self.signer).sign(canonical(self.claims)).signature
        return canonical({"claims": self.claims, "signature": base64.b64encode(signature).decode()})

    def verify(self, record=None, *, evidence=EVIDENCE, now=NOW, schema="fixture-v1", procedure=PROCEDURE):
        return verify_attestation(self.envelope() if record is None else record, evidence, bytes(self.signer.verify_key),
                                  application_schema=schema, procedure_sha256=procedure, now=now)

    def test_returns_scope_and_expiration_without_granting_restore(self):
        self.assertEqual(self.verify(), {
            "status": "RESTORE_ATTESTED", "resource_type": "docker.named-volume",
            "application_schema": "fixture-v1", "procedure_sha256": PROCEDURE,
            "tested_at": NOW - DAY, "expires_at": NOW + 89 * DAY,
            "test_archive_sha256": "b" * 64,
            "evidence_sha256": hashlib.sha256(EVIDENCE).hexdigest(),
            "restore_eligibility": "NOT_EVALUATED",
        })

    def test_expiration_is_exclusive_and_future_test_is_rejected(self):
        self.assertEqual(self.verify(now=NOW + 89 * DAY - 1)["status"], "RESTORE_ATTESTED")
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_EXPIRED"):
            self.verify(now=NOW + 89 * DAY)
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_INVALID"):
            self.verify(now=NOW - DAY - 1)

    def test_rejects_wrong_signer_tampering_and_wrong_evidence(self):
        for record in (self.envelope(signer=SigningKey.generate()),
                       self.envelope().replace(b"fixture-v1", b"fixture-v2")):
            with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_INVALID"):
                self.verify(record)
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_EVIDENCE_CHANGED"):
            self.verify(evidence=b"other record")

    def test_rejects_other_schema_and_procedure(self):
        for args in ({"schema": "fixture-v2"}, {"procedure": "c" * 64}):
            with self.subTest(args=args), self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_SCOPE_MISMATCH"):
                self.verify(**args)

    def test_rejects_a_signed_record_without_successful_negative_check(self):
        for value in (False, 1, "true"):
            self.claims["checks"]["occupied_target_refused"] = value
            with self.subTest(value=value), self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_INVALID"):
                self.verify()

    def test_source_check_combines_yesterdays_signed_archive_and_separate_owner_evidence(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        age = root / "age"
        age.write_bytes((AGE_DIR / "age").read_bytes())
        age.chmod(0o755)
        keygen = str(AGE_DIR / "age-keygen")
        identity = subprocess.run([keygen], capture_output=True, check=True).stdout
        recipient = subprocess.run([keygen, "-y"], input=identity, capture_output=True, check=True).stdout.decode().strip()
        manifest = canonical({"v": 1, "resource_type": "docker.named-volume", "application_schema": "fixture-v1",
                              "source_host": "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "source_volume": "fixture-data",
                              "captured_utc": NOW - DAY, "quiescence": "STOPPED", "overwrite": "new_empty_target_only",
                              "root": {"uid": 1000, "gid": 1000, "mode": 0o700}, "entries": []})
        archive = root / "volume.age"
        _encrypted_output(archive, recipient, {"resource/manifest.json": memoryview(manifest)},
                          age_path=age, tool_owner=os.geteuid())
        signer = SigningKey.generate()
        public_key = bytes(signer.verify_key)
        ciphertext = archive.read_bytes()
        claims = {"v": 1, "type": "hostorbit.resource-backup", "application_schema": "fixture-v1",
                  "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "recipient": recipient,
                  "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(), "ciphertext_size": len(ciphertext),
                  "age_sha256": AGE_SHA256, "signing_key_sha256": hashlib.sha256(public_key).hexdigest()}
        provenance = {"claims": claims, "signature": base64.b64encode(signer.sign(canonical(claims)).signature).decode()}
        options = {"attestation": self.envelope(), "evidence": EVIDENCE, "owner_key": bytes(self.signer.verify_key),
                   "application_schema": "fixture-v1", "procedure_sha256": PROCEDURE, "now": NOW,
                   "age_path": age, "tool_owner": os.geteuid()}
        with patch("hostorbit.runtime.resource_archive.offline_profile"):
            result = verify_restore_source(archive, provenance, public_key, identity, **options)
        self.assertEqual(result["archive"]["status"], "INTEGRITY_VERIFIED")
        self.assertEqual(result["archive"]["captured_utc"], NOW - DAY)
        self.assertEqual(result["procedure"]["status"], "RESTORE_ATTESTED")
        self.assertNotEqual(result["archive"]["ciphertext_sha256"], result["procedure"]["test_archive_sha256"])
        self.assertEqual(result["restore_eligibility"], "NOT_EVALUATED")
        options["owner_key"] = public_key
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_SEPARATE_OWNER_KEY_REQUIRED"):
            verify_restore_source(archive, provenance, public_key, identity, **options)
