import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_public_endpoint_rejects_configuration_injection(self):
        for value in ("example.org:443", "example.org/path", "localhost", "127.0.0.1",
                      "example.org\nUser=root", "Example.org", "-host.example.org"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bootstrap.WebEndpoint(value)

    def test_nginx_routes_and_certificate_sources_follow_the_endpoint(self):
        local = bootstrap.WebEndpoint()
        public = bootstrap.WebEndpoint("vpn.example.org")
        self.assertEqual(local.origin, "https://127.0.0.1:18443")
        self.assertEqual(public.origin, "https://vpn.example.org")
        self.assertEqual(public.tls_files, (Path("/etc/letsencrypt/live/vpn.example.org/fullchain.pem"),
                                           Path("/etc/letsencrypt/live/vpn.example.org/privkey.pem")))
        for endpoint in (local, public):
            with self.subTest(domain=endpoint.domain), tempfile.TemporaryDirectory() as location:
                root = Path(location)
                unit = root / "hostorbit-web.service"
                with patch.object(bootstrap, "WEB_UNIT", unit), patch.object(bootstrap, "run") as run:
                    bootstrap.start_web(endpoint)
                    service = unit.read_text()
                    self.assertIn(f"LoadCredential=web.key:{endpoint.tls_files[1]}", service)
                    self.assertIn(endpoint.origin + "/healthz", run.call_args.args)
                address, port = endpoint.bind
                config = bootstrap.nginx_config(root, root / "credentials", endpoint)
                self.assertIn(f"listen {address}:{port} ssl;", config)
                self.assertIn("proxy_pass http://127.0.0.1:18080;", config)
                self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
                self.assertEqual("IPAddressDeny=any" in service, endpoint is local)
                self.assertEqual("AmbientCapabilities=CAP_NET_BIND_SERVICE" in service, endpoint is public)

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
