from pathlib import Path
import tempfile
import unittest

from nacl.signing import SigningKey

from deploy.artifact import ArtifactError
from deploy.build_update_release import build_release, signer_from_file
from deploy.update_release import verify_candidate


class UpdateReleaseBuildTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.updater = self.root / "updater.tar.zst"
        self.updater.write_bytes(b"prepared updater")
        self.signer = SigningKey.generate()
        self.output = self.root / "candidate"

    def build(self, **changes):
        arguments = dict(release_version="1.2.0", installed="1.1.0", bootstrap="1.0.0", minimum_release="1.0.0",
                         schema=3, schema_to=4, vault_format=1,
                         images={name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")})
        return build_release(self.output, self.updater, self.signer, **(arguments | changes))

    def test_signed_candidate_round_trip_without_private_key(self):
        report = self.build()
        self.assertEqual({file.name for file in self.output.iterdir()},
                         {"release.json", "release.sig", "hostorbit-updater-linux-amd64-1.2.0.tar.zst"})
        self.assertEqual(report, verify_candidate(self.output, bytes(self.signer.verify_key),
                         installed="1.1.0", bootstrap="1.0.0", minimum_release="1.0.0", schema=3, vault_format=1))
        with self.assertRaisesRegex(ArtifactError, "UPDATE_OUTPUT_EXISTS"):
            self.build()

    def test_failure_never_publishes_candidate_or_leaves_staging_files(self):
        with self.assertRaisesRegex(ArtifactError, "UPDATE_DATA_INCOMPATIBLE"):
            self.build(schema_to=5)
        self.assertEqual(list(self.root.iterdir()), [self.updater])

    def test_signer_must_be_a_private_regular_file(self):
        seed = self.root / "signer"
        seed.touch(mode=0o600)
        seed.write_bytes(bytes(self.signer))
        self.assertEqual(bytes(signer_from_file(seed).verify_key), bytes(self.signer.verify_key))
        seed.chmod(0o644)
        with self.assertRaisesRegex(ArtifactError, "UPDATE_SIGNING_KEY_INVALID"):
            signer_from_file(seed)
