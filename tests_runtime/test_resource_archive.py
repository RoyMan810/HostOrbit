import base64
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import AGE_SHA256, trusted_age
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.rescue import _encrypted_output
from hostorbit.runtime.rescue_cli import main
from hostorbit.runtime.resource_archive import verify_archive
from test_controller_backup import AGE_DIR


class ResourceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.age = self.directory / "age"
        self.age.write_bytes((AGE_DIR / "age").read_bytes())
        self.age.chmod(0o755)
        keygen = str(AGE_DIR / "age-keygen")
        self.identity = subprocess.run([keygen], capture_output=True, check=True).stdout
        self.recipient = subprocess.run([keygen, "-y"], input=self.identity, capture_output=True, check=True).stdout.decode().strip()
        self.key = SigningKey.generate()
        self.now = int(time.time())
        self.payload = b"resource-content-canary"
        self.file = {"kind": "file", "path": "data/state", "uid": 1000, "gid": 1000, "mode": 0o600,
                     "size": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest()}
        self.manifest = {
            "v": 1, "resource_type": "docker.named-volume", "application_schema": "fixture-v1",
            "source_host": "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "source_volume": "fixture-data",
            "captured_utc": self.now - 86400, "quiescence": "STOPPED", "overwrite": "new_empty_target_only",
            "root": {"uid": 1000, "gid": 1000, "mode": 0o700},
            "entries": [{"kind": "directory", "path": "data", "uid": 1000, "gid": 1000, "mode": 0o700}, self.file],
        }
        self.enterContext(patch("hostorbit.runtime.resource_archive.offline_profile", return_value={"profile": "fixture"}))

    def archive(self, *, manifest=None, members=None, manifest_hash=None):
        path = self.directory / "volume.age"
        path.unlink(missing_ok=True)
        manifest = self.manifest if manifest is None else manifest
        raw = canonical(manifest)
        payload = members if members is not None else {"volume/data/state": memoryview(self.payload)}
        _encrypted_output(path, self.recipient, {"resource/manifest.json": memoryview(raw), **payload},
                          age_path=self.age, tool_owner=os.geteuid())
        ciphertext = path.read_bytes()
        claims = {
            "v": 1, "type": "hostorbit.resource-backup", "application_schema": manifest["application_schema"],
            "manifest_sha256": manifest_hash or hashlib.sha256(raw).hexdigest(),
            "recipient": self.recipient, "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "ciphertext_size": len(ciphertext), "age_sha256": AGE_SHA256,
            "signing_key_sha256": hashlib.sha256(bytes(self.key.verify_key)).hexdigest(),
        }
        signature = base64.b64encode(self.key.sign(canonical(claims)).signature).decode()
        return path, {"claims": claims, "signature": signature}

    def verify(self, path, envelope, *, schema="fixture-v1", key=None):
        return verify_archive(path, envelope, key or bytes(self.key.verify_key), self.identity,
                              application_schema=schema, now=self.now, age_path=self.age, tool_owner=os.geteuid())

    def test_verifies_yesterdays_archive_without_claiming_restore_eligibility(self):
        path, envelope = self.archive()
        result = self.verify(path, envelope)
        self.assertEqual(result["status"], "INTEGRITY_VERIFIED")
        self.assertEqual(result["captured_utc"], self.now - 86400)
        self.assertEqual(result["restore_eligibility"], "NOT_EVALUATED")
        self.assertEqual(result["bytes"], len(self.payload))
        self.assertNotIn(self.payload, canonical(result))
        self.assertNotIn(b"data/state", canonical(envelope))
        self.assertEqual({item.name for item in self.directory.iterdir()}, {"age", "volume.age"})

    def test_checks_anchor_and_compatibility_before_using_the_identity(self):
        path, envelope = self.archive()
        with patch("hostorbit.runtime.resource_archive.decrypt", side_effect=AssertionError("must reject before decrypt")):
            with self.assertRaisesRegex(Denied, "RESOURCE_PROVENANCE_INVALID"):
                self.verify(path, envelope, key=bytes(SigningKey.generate().verify_key))
            forged = {**envelope, "signature": base64.b64encode(bytes(64)).decode()}
            with self.assertRaisesRegex(Denied, "RESOURCE_PROVENANCE_INVALID"):
                self.verify(path, forged)
            with self.assertRaisesRegex(Denied, "RESOURCE_ARCHIVE_INCOMPATIBLE"):
                self.verify(path, envelope, schema="fixture-v2")
            modified = bytearray(path.read_bytes())
            modified[-1] ^= 1
            path.write_bytes(modified)
            with self.assertRaisesRegex(Denied, "RESOURCE_CIPHERTEXT_CHANGED"):
                self.verify(path, envelope)

    def test_rejects_incomplete_payload_even_when_correctly_signed(self):
        for members in ({}, {"volume/data/state": memoryview(b"x" * len(self.payload))},
                        {"volume/data/state": memoryview(self.payload), "volume/data/extra": memoryview(b"extra")}):
            with self.subTest(members=tuple(members)):
                path, envelope = self.archive(members=members)
                with self.assertRaisesRegex(Denied, "RESOURCE_PAYLOAD_CHANGED"):
                    self.verify(path, envelope)

    def test_rejects_a_decrypted_manifest_that_does_not_match_the_signed_digest(self):
        path, envelope = self.archive(manifest_hash="f" * 64)
        with self.assertRaisesRegex(Denied, "RESOURCE_MANIFEST_CHANGED"):
            self.verify(path, envelope)

    def test_rejects_unsafe_or_inconsistent_signed_layouts(self):
        for change in ({"path": "../escaped"}, {"path": "missing/state"}, {"mode": 0o4755}, {"path": "data"}):
            with self.subTest(change=change):
                manifest = deepcopy(self.manifest)
                manifest["entries"][1].update(change)
                path, envelope = self.archive(manifest=manifest)
                with self.assertRaisesRegex(Denied, "RESOURCE_MANIFEST_INVALID"):
                    self.verify(path, envelope)

    def test_console_reports_integrity_without_printing_payload_or_identity(self):
        path, envelope = self.archive()
        provenance, anchor = self.directory / "volume.provenance.json", self.directory / "source.pub"
        provenance.write_bytes(canonical(envelope))
        anchor.write_bytes(bytes(self.key.verify_key))
        for file in (provenance, anchor):
            file.chmod(0o600)
        secret = self.identity.decode().splitlines()[-1]
        output = io.StringIO()
        # The console still requests a root-owned binary. Exercise the same
        # pinned digest and permissions with the test runner's fixture owner.
        with (patch("hostorbit.runtime.rescue_cli.harden"),
              patch("hostorbit.runtime.rescue_cli.console"),
              patch("hostorbit.runtime.rescue_cli.offline_profile"),
              patch("hostorbit.runtime.rescue_cli.getpass.getpass", return_value=secret),
              patch("hostorbit.runtime.rescue.trusted_age",
                    side_effect=lambda path, *, owner: trusted_age(path, owner=os.geteuid())) as verify_tool,
              redirect_stdout(output)):
            self.assertEqual(main([
                "verify-resource-archive", "--ciphertext", str(path), "--provenance", str(provenance),
                "--trusted-key", str(anchor), "--application-schema", "fixture-v1", "--age-tool", str(self.age),
            ]), 0)
            verify_tool.assert_called_once_with(self.age, owner=0)
        self.assertEqual(json.loads(output.getvalue())["status"], "INTEGRITY_VERIFIED")
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(self.payload.decode(), output.getvalue())
