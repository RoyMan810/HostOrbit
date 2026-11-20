import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from deploy.artifact import ArtifactError, canonical
from deploy.update_release import verify_candidate


class UpdateReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.private = self.directory / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", self.private], check=True)
        public = subprocess.check_output(["openssl", "pkey", "-in", self.private, "-pubout", "-outform", "DER"])
        self.public = public[-32:]
        payload = b"updater candidate"
        self.archive = self.directory / "vpn-orbit-updater-linux-amd64-1.2.0.tar.zst"
        self.archive.write_bytes(payload)
        self.release = {
            "v": 1, "platform": "linux-amd64", "version": "1.2.0", "min_bootstrap_version": "1.0.0",
            "min_allowed_release": "1.1.0", "schema_compatibility": {"from": 3, "to": 4}, "vault_format": 1,
            "signing_key_id": hashlib.sha256(self.public).hexdigest(),
            "images": {name: "sha256:" + "b" * 64 for name in ("web", "api", "worker")},
            "updater": {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        }
        self.manifest = self.directory / "release.json"
        self.sign()

    def sign(self):
        self.manifest.write_bytes(canonical(self.release))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self.private, "-rawin", "-in", self.manifest,
                        "-out", self.directory / "release.sig"], check=True)

    def verify(self, **changes):
        current = {"installed": "1.1.0", "bootstrap": "1.0.0", "schema": 3, "vault_format": 1,
                   "minimum_release": "1.0.0"}
        return verify_candidate(self.directory, self.public, **(current | changes))

    def test_signed_adjacent_update_is_only_verified(self):
        report = self.verify()
        self.assertEqual((report["status"], report["schema_to"], report["applied"]), ("CANDIDATE_VERIFIED", 4, False))

    def test_changed_manifest_and_updater_bytes_fail(self):
        self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(ArtifactError, "ARTIFACT_SIGNATURE_INVALID"):
            self.verify()
        self.sign()
        self.archive.write_bytes(b"X" + self.archive.read_bytes()[1:])
        with self.assertRaisesRegex(ArtifactError, "UPDATE_UPDATER_DIGEST_MISMATCH"):
            self.verify()

    def test_signed_but_replayed_or_incompatible_release_is_denied(self):
        for changes, error in (
            ({"installed": "1.2.0"}, "UPDATE_RELEASE_TOO_OLD"),
            ({"minimum_release": "1.3.0"}, "UPDATE_RELEASE_TOO_OLD"),
            ({"bootstrap": "0.9.0"}, "UPDATE_BOOTSTRAP_INCOMPATIBLE"),
            ({"schema": 2}, "UPDATE_DATA_INCOMPATIBLE"),
            ({"vault_format": 2}, "UPDATE_DATA_INCOMPATIBLE"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ArtifactError, error):
                self.verify(**changes)
        self.release["images"]["web"] = "latest"
        self.sign()
        with self.assertRaisesRegex(ArtifactError, "UPDATE_IMAGE_DIGEST_INVALID"):
            self.verify()
