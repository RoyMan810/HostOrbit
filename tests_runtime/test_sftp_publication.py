import asyncio
import copy
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest

import asyncssh

from hostorbit.errors import Denied
from hostorbit.runtime.backup_target import BackupTarget
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.sftp_publication import publish_session
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from fixtures import ACTOR, OTHER, SECRET, TARGET, BROKER_UID, WORKER_UID, private_key, public_key


def destination():
    return {"v": 1, "enabled": True, "id": TARGET, "ip": "10.241.0.2", "port": 2223,
            "allowed_cidrs": ["10.241.0.0/30"], "host_key": public_key(), "username": "backup",
            "directory": "/store", "secret_ref": SECRET + ":v1", "policy_revision": 1}


class RemoteFile:
    def __init__(self, client, path, mode):
        self.client, self.path, self.mode, self.pos = client, path, mode, 0

    async def __aenter__(self):
        if self.mode == "xb":
            if self.path in self.client.files:
                raise asyncssh.SFTPFileAlreadyExists("fixture exists")
            self.client.files[self.path] = b""
            self.client.ops.append(("create", self.path))
        elif self.path not in self.client.files:
            raise asyncssh.SFTPNoSuchFile("fixture absent")
        return self

    async def __aexit__(self, *_):
        pass

    async def write(self, data):
        self.client.ops.append(("write", self.path))
        self.client.files[self.path] += data
        if self.client.full:
            raise asyncssh.SFTPFailure("fixture ENOSPC")

    async def read(self, size):
        data = self.client.files[self.path][self.pos:self.pos + size]
        self.pos += len(data)
        if self.client.corrupt and self.path.endswith("controller.tmp") and data:
            data = bytes([data[0] ^ 1]) + data[1:]
        return data

    async def fsync(self):
        if not self.client.supports_fsync:
            raise asyncssh.SFTPOpUnsupported("fixture missing extension")
        self.client.ops.append(("fsync", self.path))


class Remote:
    def __init__(self):
        self.files, self.dirs, self.ops = {}, {"/store"}, []
        self.full = self.corrupt = self.lost_ack = False
        self.supports_fsync = True

    def open(self, path, mode, **_):
        return RemoteFile(self, path, mode)

    async def lstat(self, path):
        if path in self.dirs:
            return SimpleNamespace(permissions=stat.S_IFDIR | 0o700, size=0)
        if path in self.files:
            return SimpleNamespace(permissions=stat.S_IFREG | 0o600, size=len(self.files[path]))
        raise asyncssh.SFTPNoSuchFile("fixture absent")

    async def mkdir(self, path, **_):
        if path in self.dirs or path in self.files:
            raise asyncssh.SFTPFileAlreadyExists("fixture exists")
        self.dirs.add(path)
        self.ops.append(("mkdir", path))

    async def listdir(self, path):
        return [p.removeprefix(path + "/") for p in self.files if p.startswith(path + "/")]

    async def rename(self, old, new):
        if new in self.files or new in self.dirs:
            raise asyncssh.SFTPFileAlreadyExists("fixture exists")
        self.ops.append(("rename", old, new))
        if old in self.dirs:
            self.dirs.remove(old)
            self.dirs.add(new)
            moved = {new + p.removeprefix(old): data for p, data in self.files.items() if p.startswith(old + "/")}
            self.files = {p: data for p, data in self.files.items() if not p.startswith(old + "/")}
            self.files.update(moved)
            if self.lost_ack:
                raise asyncssh.ConnectionLost("fixture lost final ACK")
        else:
            self.files[new] = self.files.pop(old)


class SftpProtocolTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.cipher = self.root / "controller.age"
        self.cipher.write_bytes(os.urandom(200000))
        self.claims = {"ciphertext_size": self.cipher.stat().st_size,
                       "ciphertext_sha256": hashlib.sha256(self.cipher.read_bytes()).hexdigest()}
        self.target = BackupTarget.parse(destination())
        self.remote = Remote()

    def publish(self, check=lambda: None):
        return asyncio.run(publish_session(self.remote, self.target, OTHER, self.cipher, self.claims, b"signed-envelope", check))

    def test_complete_marker_is_exposed_only_after_fsync_and_all_readbacks(self):
        receipt = self.publish()
        final = "/store/" + OTHER
        self.assertTrue(receipt["verified"])
        self.assertEqual(set(self.remote.files), {final + "/controller.age", final + "/provenance.json", final + "/COMPLETE"})
        self.assertEqual(len([op for op in self.remote.ops if op[0] == "fsync"]), 3)
        self.assertEqual(self.remote.ops[-1][0], "rename")
        self.assertEqual(self.remote.ops[-1][-1], final)

    def test_corruption_enospc_or_unsupported_fsync_cannot_publish(self):
        for fault, expected in (("corrupt", Denied), ("full", asyncssh.SFTPError), ("supports_fsync", asyncssh.SFTPError)):
            with self.subTest(fault=fault):
                self.remote = Remote()
                setattr(self.remote, fault, fault != "supports_fsync")
                with self.assertRaises(expected):
                    self.publish()
                self.assertNotIn("/store/" + OTHER, self.remote.dirs)
                self.assertFalse(any(p == "/store/" + OTHER + "/COMPLETE" for p in self.remote.files))

    def test_lost_final_ack_is_reconciled_without_overwriting_or_reupload(self):
        self.remote.lost_ack = True
        with self.assertRaises(asyncssh.ConnectionLost):
            self.publish()
        before = copy.deepcopy(self.remote.files)
        ops = len(self.remote.ops)
        self.remote.lost_ack = False
        self.assertTrue(self.publish()["verified"])
        self.assertEqual(before, self.remote.files)
        self.assertEqual(len(self.remote.ops), ops)

    def test_existing_corrupt_archive_is_never_replaced(self):
        self.publish()
        self.remote.files["/store/" + OTHER + "/controller.age"] = b"bad"
        before = copy.deepcopy(self.remote.files)
        with self.assertRaisesRegex(Denied, "SFTP_READBACK_MISMATCH"):
            self.publish()
        self.assertEqual(before, self.remote.files)

    def test_revocation_at_a_checkpoint_prevents_the_final_promotion(self):
        def revoked():
            if any(p.endswith("/provenance.json") for p in self.remote.files):
                raise Denied("SECRET_NOT_ACTIVE")
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.publish(revoked)
        self.assertNotIn("/store/" + OTHER, self.remote.dirs)

    def test_wrong_local_digest_leaves_only_incomplete_staging(self):
        self.cipher.write_bytes(b"changed")
        with self.assertRaisesRegex(Denied, "SFTP_LOCAL_SOURCE_CHANGED"):
            self.publish()
        self.assertNotIn("/store/" + OTHER, self.remote.dirs)


class BackupCredentialTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        new_private_file(self.root / "credential", os.urandom(32))
        self.vault = Vault.initialize(self.root / "vault", self.root / "credential")

    def test_sftp_and_probe_consumers_targets_and_revisions_are_not_interchangeable(self):
        key = private_key()
        ref = self.vault.import_backup_ssh(SECRET, 1, key, owner_id=ACTOR, broker_uid=BROKER_UID, target=TARGET)
        self.assertEqual(self.vault.use_backup_ssh(ref, broker_uid=BROKER_UID, target=TARGET, policy_revision=1), key)
        for kwargs in ({"broker_uid": WORKER_UID, "target": TARGET, "policy_revision": 1},
                       {"broker_uid": BROKER_UID, "target": OTHER, "policy_revision": 1},
                       {"broker_uid": BROKER_UID, "target": TARGET, "policy_revision": 2}):
            with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
                self.vault.use_backup_ssh(ref, **kwargs)
        with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
            self.vault.use_ssh(ref, worker_uid=BROKER_UID, target=TARGET)
        probe = self.vault.import_ssh(SECRET, 2, key, owner_id=ACTOR, worker_uid=BROKER_UID, target=TARGET)
        with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
            self.vault.use_backup_ssh(probe, broker_uid=BROKER_UID, target=TARGET, policy_revision=1)
        self.vault.revoke(ref)
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_backup_ssh(ref, broker_uid=BROKER_UID, target=TARGET, policy_revision=1)

    def test_destination_rejects_dns_metadata_loopback_paths_and_unknown_fields(self):
        for field, value in (("ip", "localhost"), ("ip", "127.0.0.1"), ("ip", "169.254.169.254"),
                             ("ip", "::ffff:10.241.0.2"), ("directory", "/store/../root"),
                             ("directory", "/store//more"), ("directory", "/"), ("username", "root;anything")):
            with self.subTest(field=field, value=value):
                with self.assertRaises(Denied):
                    BackupTarget.parse({**destination(), field: value})
        self.assertIsNone(BackupTarget.parse({"v": 1, "enabled": False}))
        with self.assertRaises(Denied):
            BackupTarget.parse({"v": 1, "enabled": 0})


if __name__ == "__main__":
    unittest.main()
