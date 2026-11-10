import base64
from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
import sqlite3
import stat
from pathlib import Path
import subprocess
import tempfile
import unittest
from uuid import uuid4
from unittest.mock import patch

from nacl.signing import SigningKey

from hostorbit.errors import Denied
from hostorbit.runtime.archive_stream import AGE_SHA256
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.rescue import _encrypted_output
from hostorbit.runtime.resource_restore_cli import main
from hostorbit.runtime.resource_restore_attestation import verify_attestation, verify_restore_source
from hostorbit.runtime.resource_restore_stage import stage_restore_source
from hostorbit.runtime.resource_restore_target import check_restore_target
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

    def signed_source(self, payload=b"yesterday's fixture state"):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        age = root / "age"
        age.write_bytes((AGE_DIR / "age").read_bytes())
        age.chmod(0o755)
        keygen = str(AGE_DIR / "age-keygen")
        identity = subprocess.run([keygen], capture_output=True, check=True).stdout
        recipient = subprocess.run([keygen, "-y"], input=identity, capture_output=True, check=True).stdout.decode().strip()
        metadata = {"uid": os.geteuid(), "gid": os.getegid(), "mode": 0o750}
        entries = [
            {"kind": "file", "path": "state/database", **metadata, "mode": 0o640,
             "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
            {"kind": "directory", "path": "state", **metadata},
            {"kind": "file", "path": "empty", **metadata, "mode": 0o400,
             "size": 0, "sha256": hashlib.sha256(b"").hexdigest()},
        ]
        manifest = canonical({"v": 1, "resource_type": "docker.named-volume", "application_schema": "fixture-v1",
                              "source_host": "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "source_volume": "fixture-data",
                              "captured_utc": NOW - DAY, "quiescence": "STOPPED", "overwrite": "new_empty_target_only",
                              "root": metadata, "entries": entries})
        archive = root / "volume.age"
        _encrypted_output(archive, recipient, {"resource/manifest.json": memoryview(manifest),
                                               "volume/state/database": memoryview(payload)},
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
        self.enterContext(patch("hostorbit.runtime.resource_archive.offline_profile"))
        self.enterContext(patch("hostorbit.runtime.resource_restore_stage.offline_profile"))
        return root, payload, (archive, provenance, public_key, identity), options

    def test_source_check_combines_yesterdays_signed_archive_and_separate_owner_evidence(self):
        _, _, args, options = self.signed_source()
        result = verify_restore_source(*args, **options)
        self.assertEqual(result["archive"]["status"], "INTEGRITY_VERIFIED")
        self.assertEqual(result["archive"]["captured_utc"], NOW - DAY)
        self.assertEqual(result["procedure"]["status"], "RESTORE_ATTESTED")
        self.assertNotEqual(result["archive"]["ciphertext_sha256"], result["procedure"]["test_archive_sha256"])
        self.assertEqual(result["restore_eligibility"], "NOT_EVALUATED")
        options["owner_key"] = args[2]
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_SEPARATE_OWNER_KEY_REQUIRED"):
            verify_restore_source(*args, **options)

    def test_stages_verified_yesterdays_data_once_with_signed_metadata(self):
        root, payload, args, options = self.signed_source()
        destination = root / "staged"
        result = stage_restore_source(*args, destination=destination, **options)
        self.assertEqual(result["status"], "RESTORE_STAGED")
        self.assertEqual(result["archive"]["captured_utc"], NOW - DAY)
        self.assertEqual(result["restore_eligibility"], "NOT_EVALUATED")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual({p.name for p in destination.iterdir()}, {"data"})
        self.assertEqual((destination / "data/state/database").read_bytes(), payload)
        self.assertEqual((destination / "data/empty").read_bytes(), b"")
        for name, mode in (("data", 0o750), ("data/state", 0o750),
                           ("data/state/database", 0o640), ("data/empty", 0o400)):
            metadata = (destination / name).stat()
            self.assertEqual((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
                             (os.geteuid(), os.getegid(), mode))
        with self.assertRaisesRegex(Denied, "RESTORE_STAGE_TARGET_EXISTS"):
            stage_restore_source(*args, destination=destination, **options)
        self.assertEqual((destination / "data/state/database").read_bytes(), payload)

    def test_rejects_untrusted_parent_and_invalid_attestation_before_staging(self):
        root, _, args, options = self.signed_source()
        alias = root / "alias"
        alias.symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(Denied, "RESTORE_STAGE_TARGET_UNTRUSTED"):
            stage_restore_source(*args, destination=alias / "staged", **options)
        with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_EVIDENCE_CHANGED"):
            stage_restore_source(*args, destination=root / "staged", **{**options, "evidence": b"other"})
        self.assertFalse((root / "staged").exists())

    def test_modified_ciphertext_never_reserves_a_destination(self):
        root, _, args, options = self.signed_source()
        archive = args[0]
        content = archive.read_bytes()
        archive.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
        destination = root / "staged"
        with self.assertRaisesRegex(Denied, "RESOURCE_CIPHERTEXT_CHANGED"):
            stage_restore_source(*args, destination=destination, **options)
        self.assertFalse(destination.exists())

    def test_failed_write_consumes_the_reservation_without_publishing_data(self):
        root, _, args, options = self.signed_source()
        destination = root / "staged"
        with patch("hostorbit.runtime.resource_restore_stage.new_private_file", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(Denied, "RESTORE_STAGE_WRITE_FAILED"):
                stage_restore_source(*args, destination=destination, **options)
        self.assertTrue(destination.is_dir())
        self.assertFalse((destination / "data").exists())
        with self.assertRaisesRegex(Denied, "RESTORE_STAGE_TARGET_EXISTS"):
            stage_restore_source(*args, destination=destination, **options)

    def test_staging_cli_requires_independent_digest_before_reading_the_identity(self):
        root, _, source, options = self.signed_source()
        archive, provenance, key, _ = source
        for name, content in (("provenance", canonical(provenance)), ("archive-key", key),
                              ("owner-key", options["owner_key"]), ("attestation", options["attestation"]),
                              ("evidence", options["evidence"])):
            (root / name).write_bytes(content)
        args = ["--ciphertext", str(archive),
                "--provenance", str(root / "provenance"), "--trusted-key", str(root / "archive-key"),
                "--owner-key", str(root / "owner-key"), "--attestation", str(root / "attestation"),
                "--evidence", str(root / "evidence"), "--destination", str(root / "staged"),
                "--application-schema", options["application_schema"], "--procedure-sha256", PROCEDURE]
        error = io.StringIO()
        with (patch("hostorbit.runtime.resource_restore_cli.harden"),
              patch("hostorbit.runtime.resource_restore_cli.offline_profile"),
              patch("hostorbit.runtime.resource_restore_cli.console"),
              patch("builtins.input", return_value="0" * 64),
              patch("hostorbit.runtime.resource_restore_cli.getpass.getpass") as read_identity,
              redirect_stderr(error), redirect_stdout(io.StringIO())):
            self.assertEqual(main(args), 2)
        read_identity.assert_not_called()
        self.assertEqual(error.getvalue().splitlines()[-1], "RESTORE_STAGE_CONFIRMATION_MISMATCH")
        self.assertFalse((root / "staged").exists())

    @unittest.skipUnless(os.environ.get("HOSTORBIT_LAB_RESTORE_IMAGE"), "requires disposable Docker CI")
    def test_restored_data_is_usable_in_a_new_docker_volume(self):
        self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true")
        self.assertEqual(os.geteuid(), 0)
        image = os.environ["HOSTORBIT_LAB_RESTORE_IMAGE"]

        def docker(*args):
            return subprocess.run(["/usr/bin/docker", *args], check=True, capture_output=True, timeout=60).stdout

        with closing(sqlite3.connect(":memory:")) as source:
            source.execute("CREATE TABLE settings(value TEXT NOT NULL)")
            source.execute("INSERT INTO settings VALUES ('recovered')")
            source.commit()
            payload = source.serialize()
        root, _, args, options = self.signed_source(payload)
        destination = root / "staged"
        stage_restore_source(*args, destination=destination, **options)

        name = f"hostorbit-ac-b05-{uuid4().hex}"
        docker("volume", "create", name)
        self.addCleanup(docker, "volume", "rm", name)
        volume, = json.loads(docker("volume", "inspect", name))
        docker_root = Path(docker("info", "--format", "{{.DockerRootDir}}").decode().strip())
        target = {"expected_created_at": volume["CreatedAt"], "docker_root": docker_root,
                  "required_bytes": len(payload), "required_inodes": 3}
        self.assertEqual(check_restore_target(name, **target)["status"], "EMPTY_TARGET_CHECKED")

        mount = f"type=volume,src={name},dst=/volume,volume-nocopy"
        docker("run", "--rm", "--network", "none", "--mount", mount,
               "--mount", f"type=bind,src={destination / 'data'},dst=/restore,readonly",
               image, "cp", "-a", "/restore/.", "/volume/")
        check_application = (
            "import os, sqlite3; "
            "path = '/volume/state/database'; "
            "assert (os.stat(path).st_mode & 0o777, os.stat(path).st_uid, os.stat(path).st_gid) == (0o640, 0, 0); "
            "db = sqlite3.connect('file:' + path + '?mode=ro', uri=True); "
            "assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',); "
            "assert db.execute('SELECT value FROM settings').fetchone() == ('recovered',)"
        )
        docker("run", "--rm", "--network", "none", "--mount", mount + ",readonly",
               image, "python", "-c", check_application)
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_OCCUPIED"):
            check_restore_target(name, **target)
