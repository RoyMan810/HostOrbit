"""Signed input and namespace contracts, independent of the disposable root install lab."""

import copy
import hashlib
import os
from pathlib import Path
import sys
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest

from nacl.signing import SigningKey

from hostorbit.errors import Denied
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.storage import _credential_permissions

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
sys.path.insert(0, str(DEPLOY))
from artifact import ArtifactError, FIXED_FILES, canonical, manifest, snapshot, trusted_key
from installer import compose_document, origin


class InstallationTests(unittest.TestCase):
    def test_systemd_credential_allows_only_readonly_exact_broker_acl_or_owner_fallback(self):
        owner = 23103
        entries = [(1, 4, 0xffffffff), (2, 4, owner), (4, 0, 0xffffffff),
                   (16, 4, 0xffffffff), (32, 0, 0xffffffff)]
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0, st_size=32, st_nlink=1)
        self.assertTrue(_credential_permissions(info, acl, owner, True))
        self.assertFalse(_credential_permissions(info, acl, owner, False))
        self.assertFalse(_credential_permissions(info, acl, owner + 1, True))
        self.assertFalse(_credential_permissions(info, None, owner, True))
        for position in (1, 2, 4):
            changed = list(entries)
            tag, _, uid = changed[position]
            changed[position] = (tag, 5 if position == 1 else 4, uid)
            broad_acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in changed)
            self.assertFalse(_credential_permissions(info, broad_acl, owner, True))
        info.st_uid, info.st_mode = owner, stat.S_IFREG | 0o400
        self.assertTrue(_credential_permissions(info, None, owner, True))
        for field, value in (("st_mode", stat.S_IFREG | 0o600), ("st_uid", owner + 1), ("st_nlink", 2), ("st_size", 31)):
            altered = SimpleNamespace(**{**vars(info), field: value})
            self.assertFalse(_credential_permissions(altered, None, owner, True))

    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bundle = self.directory / "bundle"
        self.bundle.mkdir()
        self.signer = SigningKey.generate()
        self.key = bytes(self.signer.verify_key)
        self.private_seed = self.directory / "offline-signing-key"
        self.private_seed.write_bytes(bytes(self.signer))
        self.contents = {path: ("fixture " + path).encode() for path in FIXED_FILES}
        self.contents["wheelhouse/hostorbit-0.1.0.dev1-py3-none-any.whl"] = b"fixture-wheel"
        for name, content in self.contents.items():
            p = self.bundle / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        self.value = {"v": 1, "application": "HostOrbit", "version": "0.1.0.dev1", "channel": "development",
                      "source_commit": "a" * 40, "python_image": "docker.io/library/python@sha256:" + "b" * 64,
                      "platform": "ubuntu-24.04-amd64", "python": "3.13", "sqlite_schema": 2,
                      "remote_mutation_enabled": False, "signing_key_sha256": hashlib.sha256(self.key).hexdigest(),
                      "files": [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                for name, data in sorted(self.contents.items())]}
        self.sign()

    def sign(self):
        raw = canonical(self.value)
        (self.bundle / "manifest.json").write_bytes(raw)
        (self.bundle / "manifest.sig").write_bytes(self.signer.sign(raw).signature)

    def test_verified_copy_has_only_signed_files_and_never_copies_the_offline_seed(self):
        (self.bundle / "unexpected.py").write_text("not signed")
        dest = self.directory / "verified"
        value, digest = snapshot(self.bundle, dest, self.key, allow_development=True)
        self.assertEqual(value, self.value)
        self.assertEqual(digest, hashlib.sha256(canonical(self.value)).hexdigest())
        self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
        for name, content in self.contents.items():
            self.assertEqual((dest / name).read_bytes(), content)
        self.assertFalse((dest / "unexpected.py").exists())
        self.assertFalse(any(p.read_bytes() == bytes(self.signer) for p in dest.rglob("*") if p.is_file()))

    def test_signature_other_key_modified_manifest_and_wheel_fail_before_execution(self):
        with self.assertRaisesRegex(ArtifactError, "SIGNATURE_INVALID"):
            manifest(self.bundle, bytes(SigningKey.generate().verify_key), allow_development=True)
        (self.bundle / "manifest.json").write_bytes(canonical({**self.value, "source_commit": "c" * 40}))
        with self.assertRaisesRegex(ArtifactError, "SIGNATURE_INVALID"):
            manifest(self.bundle, self.key, allow_development=True)
        self.sign()
        (self.bundle / "wheelhouse/hostorbit-0.1.0.dev1-py3-none-any.whl").write_bytes(b"tampered")
        with self.assertRaisesRegex(ArtifactError, "DIGEST_MISMATCH"):
            snapshot(self.bundle, self.directory / "bad", self.key, allow_development=True)

    def test_signed_paths_duplicates_unsupported_schema_and_mutation_cannot_expand_the_bootstrap(self):
        original = copy.deepcopy(self.value)
        for field, changed in (("sqlite_schema", 99), ("remote_mutation_enabled", True), ("python_image", "python:latest")):
            with self.subTest(field=field):
                self.value = {**copy.deepcopy(original), field: changed}
                self.sign()
                with self.assertRaises(ArtifactError):
                    manifest(self.bundle, self.key, allow_development=True)
        for path in ("../root-exec", "/root-exec", "wheelhouse/../escape.whl", "deploy/unknown.py"):
            self.value = copy.deepcopy(original)
            self.value["files"][0]["path"] = path
            self.sign()
            with self.subTest(path=path), self.assertRaisesRegex(ArtifactError, "FILES_INVALID"):
                manifest(self.bundle, self.key, allow_development=True)
        self.value = copy.deepcopy(original)
        self.value["files"].append(self.value["files"][0])
        self.sign()
        with self.assertRaisesRegex(ArtifactError, "FILES_INVALID"):
            manifest(self.bundle, self.key, allow_development=True)

    def test_parent_or_file_symlink_and_hardlinks_are_not_followed(self):
        wheel = self.bundle / "wheelhouse/hostorbit-0.1.0.dev1-py3-none-any.whl"
        for kind in ("file", "parent", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "file":
                    wheel.unlink()
                    wheel.symlink_to(self.private_seed)
                elif kind == "parent":
                    wheel.unlink()
                    wheel.parent.rmdir()
                    wheel.parent.symlink_to(self.directory)
                else:
                    wheel.parent.unlink()
                    wheel.parent.mkdir()
                    os.link(self.private_seed, wheel)
                with self.assertRaises((OSError, ArtifactError)):
                    snapshot(self.bundle, self.directory / kind, self.key, allow_development=True)

    def test_unsigned_development_opt_in_and_broad_trust_key_permissions_are_denied(self):
        with self.assertRaisesRegex(ArtifactError, "CONTRACT_UNSUPPORTED"):
            manifest(self.bundle, self.key)
        public = self.directory / "release-trust.pub"
        public.write_bytes(self.key)
        public.chmod(0o600)
        self.assertEqual(trusted_key(public, owner=os.geteuid()), self.key)
        public.chmod(0o666)
        with self.assertRaisesRegex(ArtifactError, "TRUST_KEY_PERMISSIONS"):
            trusted_key(public, owner=os.geteuid())

    def test_compose_separates_public_api_from_networkless_worker_and_private_host_data(self):
        cfg = {"app_uid": 23101, "app_gid": 23201, "worker_uid": 23102, "worker_gid": 23102,
               "broker_rpc_gid": 23202, "gate_rpc_gid": 23203}
        doc = compose_document(cfg, "hostorbit/controller:fixture", 18080)
        api, worker = doc["services"]["api"], doc["services"]["worker"]
        self.assertEqual(api["ports"], [{"target": 8000, "published": "18080", "host_ip": "127.0.0.1", "protocol": "tcp"}])
        self.assertEqual(worker["network_mode"], "none")
        self.assertNotIn("ports", worker)
        self.assertEqual(worker["group_add"], ["23201", "23202", "23203"])
        self.assertNotIn("group_add", api)
        self.assertEqual(set(doc["services"]), {"api", "worker"})
        for service in (api, worker):
            self.assertEqual(service["userns_mode"], "host")
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertTrue(service["read_only"])
            for volume in service["volumes"]:
                self.assertFalse(volume["bind"]["create_host_path"])
                self.assertNotIn("credentials", volume["source"])
                self.assertNotIn("control-gate", volume["source"])
                self.assertNotIn("vault", volume["source"])
                self.assertNotIn("docker.sock", volume["source"])
        self.assertFalse(any("/run/hostorbit/" in p["source"] for p in api["volumes"]))

    def test_fresh_empty_policy_has_no_capability_and_origin_must_remain_https(self):
        policy = Policy([])
        self.assertEqual(policy.targets, {})
        with self.assertRaisesRegex(Denied, "CAPABILITY_DISABLED"):
            policy.target("unregistered", "host.probe", "a" * 64)
        self.assertEqual(origin("https://hostorbit.test"), "https://hostorbit.test")
        for invalid in ("http://hostorbit.test", "https://hostorbit.test/", "https://a:b@hostorbit.test", "https://hostorbit.test:443"):
            with self.subTest(origin=invalid), self.assertRaises(ArtifactError):
                origin(invalid)
