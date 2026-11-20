import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_bundle_checkout_is_detached_and_uses_only_committed_files(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location)
            checkout = root / "checkout"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", checkout], check=True)
            tracked = checkout / "app.txt"
            tracked.write_text("committed")
            subprocess.run(["git", "-C", checkout, "add", "app.txt"], check=True)
            subprocess.run(["git", "-C", checkout, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.org",
                            "commit", "-qm", "Fixture"], check=True)
            revision = bootstrap.capture("git", "-C", checkout, "rev-parse", "HEAD")
            subprocess.run(["git", "-C", checkout, "checkout", "-q", "--detach", revision], check=True)
            tracked.write_text("changed")
            (checkout / "untracked.txt").write_text("untracked")
            bundle = root / "source.bundle"
            subprocess.run(["git", "-C", checkout, "bundle", "create", bundle, "HEAD"], check=True)
            target = root / "build"
            bootstrap.materialize_checkout(bundle, target, revision)
            self.assertEqual("committed", (target / "app.txt").read_text())
            self.assertFalse((target / "untracked.txt").exists())
            self.assertNotEqual(0, subprocess.run(["git", "-C", target, "symbolic-ref", "-q", "HEAD"]).returncode)
            with self.assertRaisesRegex(ValueError, "Ревизия checkout"):
                bootstrap.materialize_checkout(bundle, root / "wrong", "0" * 40)

    def test_python_build_jobs_are_limited_by_memory_and_cpus(self):
        gib = 1024**2
        self.assertEqual(bootstrap.python_build_jobs(8, gib // 2), 1)
        self.assertEqual(bootstrap.python_build_jobs(8, 2 * gib), 2)
        self.assertEqual(bootstrap.python_build_jobs(2, 8 * gib), 2)
        self.assertEqual(bootstrap.python_build_jobs(8, 8 * gib), 4)

    def test_download_rejects_archive_with_wrong_digest(self):
        with tempfile.TemporaryDirectory() as location:
            output = Path(location) / "archive"
            output.write_bytes(b"unverified")
            with patch.object(bootstrap, "run") as run:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    bootstrap.download("https://example.org", output, "0" * 64)
                bootstrap.download("https://example.org", output, hashlib.sha256(b"unverified").hexdigest())
                self.assertIn("=https", run.call_args.args)


if __name__ == "__main__":
    unittest.main()
