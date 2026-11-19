import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from nacl.signing import SigningKey

from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import trusted_age
from hostorbit.runtime import resource_capture as capture
from hostorbit.runtime.resource_archive import verified_archive
from test_controller_backup import AGE_DIR, fixture_identity


class ResourceCaptureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.private = SigningKey.generate()
        self.identity, self.public = fixture_identity()
        self.name = "hostorbit-source-" + uuid4().hex
        self.created = "2026-01-01T00:00:00Z"
        self.age = self.root / "age"
        self.age.write_bytes((AGE_DIR / "age").read_bytes())
        self.age.chmod(0o755)
        self.destination = self.root / "archive"
        self.options = dict(created_at=self.created, source_host="01JCYQZ4T9V8MNVYEH3D2M7Q1A",
                            application_schema="fixture-v1", public=self.public, signing_key=self.private,
                            destination=self.destination, age_path=self.age)

    def source_tree(self):
        docker = self.root / "docker"
        tree = docker / "volumes" / self.name / "_data"
        tree.mkdir(parents=True)
        self.enterContext(patch.object(capture, "_ROOT", docker))
        self.enterContext(patch.object(capture, "_require_private_docker"))
        self.enterContext(patch("hostorbit.runtime.rescue.trusted_age",
                               side_effect=lambda path, owner: trusted_age(path, owner=os.geteuid())))
        return tree

    def verify(self):
        record = json.loads((self.destination / "volume.provenance.json").read_bytes())
        return verified_archive(self.destination / "volume.age", record, bytes(self.private.verify_key),
                                self.identity, application_schema="fixture-v1", now=2**32,
                                age_path=self.age, tool_owner=os.geteuid())

    def test_generated_archive_verifies_bytes_empty_files_and_metadata(self):
        tree = self.source_tree()
        (tree / "nested").mkdir()
        (tree / "nested/state").write_bytes(b"saved")
        (tree / "nested/state").chmod(0o640)
        (tree / "empty").touch()
        with patch.object(capture, "_stopped", return_value=[]):
            capture.capture_volume(self.name, **self.options)
            with self.assertRaises(FileExistsError):
                capture.capture_volume(self.name, **self.options)
        with self.verify() as (manifest, members, total, _):
            self.assertEqual(manifest["source_volume"], self.name)
            self.assertEqual(total, 5)
            self.assertEqual(members, {"volume/nested/state": b"saved"})
            entries = {item["path"]: item for item in manifest["entries"]}
            self.assertEqual(entries["empty"]["size"], 0)
            self.assertEqual(entries["nested/state"]["mode"], 0o640)

    def test_refuses_symlink_and_a_change_in_consumers(self):
        tree = self.source_tree()
        (tree / "alias").symlink_to(self.root)
        with patch.object(capture, "_stopped", return_value=[]):
            with self.assertRaisesRegex(Denied, "CAPTURE_ENTRY_UNSUPPORTED"):
                capture.capture_volume(self.name, **self.options)
        (tree / "alias").unlink()
        with patch.object(capture, "_stopped", side_effect=[[], [("other", "exited")]]):
            with self.assertRaisesRegex(Denied, "CAPTURE_SOURCE_CHANGED"):
                capture.capture_volume(self.name, **self.options)
        self.assertFalse(self.destination.exists())

    @unittest.skipUnless(os.environ.get("HOSTORBIT_LAB_RESTORE_IMAGE"), "requires disposable Docker CI")
    def test_docker_volume_cli(self):
        self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
        self.assertEqual(os.geteuid(), 0)
        image = os.environ["HOSTORBIT_LAB_RESTORE_IMAGE"]

        def docker(*args):
            return subprocess.run(["/usr/bin/docker", *args], check=True, capture_output=True,
                                  timeout=60).stdout.decode().strip()

        sock = Path("/run/docker.sock")
        mode = stat.S_IMODE(sock.stat().st_mode)
        sock.chmod(0o600)
        self.addCleanup(sock.chmod, mode)
        docker("volume", "create", self.name)
        self.addCleanup(docker, "volume", "rm", self.name)
        created = docker("volume", "inspect", "--format", "{{.CreatedAt}}", self.name)
        mount = f"type=volume,src={self.name},dst=/volume,volume-nocopy"
        container = docker("run", "--detach", "--network=none", "--mount", mount, image,
                           "sh", "-c", "echo persisted > /volume/state && exec sleep 300")
        self.addCleanup(docker, "rm", "-f", container)
        with self.assertRaisesRegex(Denied, "CAPTURE_SOURCE_ACTIVE"):
            capture.capture_volume(self.name, **{**self.options, "created_at": created})
        self.assertFalse(self.destination.exists())
        docker("exec", container, "test", "-s", "/volume/state")
        docker("stop", "-t", "1", container)
        seed = self.root / "archive.seed"
        seed.write_bytes(bytes(self.private))
        seed.chmod(0o600)
        with redirect_stdout(io.StringIO()), patch.object(capture, "harden"):
            self.assertEqual(capture.main(["--volume", self.name, "--created-at", created, "--source-host",
                                           self.options["source_host"], "--application-schema", "fixture-v1",
                                           "--recipient", self.public, "--destination", str(self.destination),
                                           "--signing-key", str(seed), "--age-tool", str(self.age)]), 0)
        with self.verify() as (_, members, _, _):
            self.assertEqual(members["volume/state"], b"persisted\n")
