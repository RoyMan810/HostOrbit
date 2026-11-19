from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import asyncssh

from hostorbit.admission import Admission
from hostorbit.errors import Denied
from hostorbit.runtime.cli import main
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.backup_target import BackupTarget
from test_sftp_publication import destination
from hostorbit.runtime.storage import new_private_file
from hostorbit.runtime.vault import Vault
from fixtures import ACTOR, OTHER, SECRET, TARGET, WORKER_UID, policy, private_key


class KeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.writers = Admission.initialize(self.root / "writers", owner=os.geteuid())
        self.writers.publish("OPEN")
        credential = self.root / "dek"
        new_private_file(credential, os.urandom(32))
        self.vault = Vault.initialize(self.root / "vault", credential)
        self.vault.journal.writers = self.writers
        self.config = dict(app_uid=1, app_gid=2, broker_uid=os.geteuid(), worker_uid=WORKER_UID,
                           writer_directory=str(self.writers.directory), targets="/targets",
                           vault_directory=str(self.vault.directory), vault_credential=str(credential))
        self.enterContext(patch("hostorbit.runtime.cli.configuration", return_value=self.config))
        self.policy = self.enterContext(patch("hostorbit.runtime.cli.Policy.load", return_value=policy()))
        self.enterContext(patch("hostorbit.runtime.cli.Admission", return_value=self.writers))
        self.first = self.vault.import_ssh(SECRET, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
        self.keyfile = self.root / "new-key"
        new_private_file(self.keyfile, self.key)
        self.scope = dict(anchor=self.first, scope_digest=policy().targets[TARGET].scope_digest, purpose="host.probe", target=TARGET, policy_revision=1, consumer_uid=WORKER_UID)

    def command(self, name, ref, revision=1, *, purpose="host.probe", target=TARGET):
        args = ["--config", "/runtime", name, "--target", target, "--purpose", purpose,
                "--reference", ref, "--policy-revision", str(revision)]
        if name == "rotate-key":
            args += ["--key-file", str(self.keyfile)]
        with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
            code = main(args)
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_operator_rotation_revoke_and_old_vault_upgrade(self):
        with self.vault.journal.write() as db:
            db.execute("DROP TABLE secret_lifecycle")
        second = SECRET + ":v2"
        self.assertEqual(self.command("rotate-key", self.first), (0, second, ""))
        self.assertEqual(self.command("rotate-key", self.first), (1, "", "SECRET_SCOPE_DENIED"))
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_ssh(self.first, worker_uid=WORKER_UID, target=TARGET)
        self.assertEqual(self.vault.use_ssh(second, worker_uid=WORKER_UID, target=TARGET, policy_revision=1), self.key)
        self.assertEqual(self.vault.use_policy_key(**self.scope), self.key)
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_policy_key(**(self.scope | {"scope_digest": "0"*64}))
        self.assertEqual(self.command("revoke-key", second), (0, "REVOKED", ""))
        self.assertEqual(self.command("revoke-key", second), (1, "", "SECRET_NOT_ACTIVE"))
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_ssh(second, worker_uid=WORKER_UID, target=TARGET, policy_revision=2)
        with self.vault.journal.connect() as db:
            rows = [tuple(row) for row in db.execute("SELECT ref,replacement,target,owner_id,purpose,policy_revision,broker_uid "
                                                      "FROM secret_lifecycle ORDER BY ref")]
            self.assertEqual(rows, [(self.first, second, TARGET, ACTOR, "host.probe", 1, os.geteuid()),
                                    (second, None, TARGET, ACTOR, "host.probe", 1, os.geteuid())])
        for file in self.vault.directory.rglob("*"):
            if file.is_file():
                self.assertNotIn(b"PRIVATE KEY", file.read_bytes())

    def test_only_committed_successors_follow_the_anchor(self):
        second = self.command("rotate-key", self.first)[1]
        third_key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
        self.keyfile.write_bytes(third_key)
        third = SECRET + ":v3"
        self.assertEqual(self.command("rotate-key", second), (0, third, ""))
        self.assertEqual(self.vault.use_policy_key(**self.scope, exact_ref=third), third_key)
        for retired in [self.first, second]:
            with self.assertRaisesRegex(Denied, "BROKER_SCOPE_DENIED"):
                self.vault.use_policy_key(**self.scope, exact_ref=retired)
        self.vault.import_ssh(SECRET, 4, self.key, owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.assertEqual(self.command("revoke-key", third), (0, "REVOKED", ""))
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_policy_key(**self.scope)

    def test_failures_leave_current_key_available(self):
        for args in ({"target": OTHER}, {"revision": 2}, {"purpose": "docker.restart"}):
            self.assertEqual(self.command("revoke-key", self.first, **args), (1, "", "SECRET_SCOPE_DENIED"))
        self.assertEqual(self.command("revoke-key", SECRET + ":v2"), (1, "", "SECRET_SCOPE_DENIED"))
        self.keyfile.write_bytes(private_key())
        self.assertEqual(self.command("rotate-key", self.first), (1, "", "SECRET_NEW_KEY_REQUIRED"))
        self.keyfile.write_bytes(b"KEY-CONTENTS-CANARY")
        self.assertEqual(self.command("rotate-key", self.first), (1, "", "SSH_KEY_FORMAT_UNSUPPORTED"))
        self.keyfile.write_bytes(self.key)
        self.vault.import_ssh(SECRET, 2, self.key, owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.assertEqual(self.command("rotate-key", self.first), (1, "", "SECRET_VERSION_IMMUTABLE"))
        self.assertEqual(self.vault.use_ssh(self.first, worker_uid=WORKER_UID, target=TARGET), private_key())
        with self.vault.journal.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM secret_lifecycle").fetchone()[0], 0)

        self.writers.publish("READ_ONLY_RECOVERY")
        self.assertEqual(self.command("rotate-key", self.first), (1, "", "WRITER_ADMISSION_CLOSED"))

    def test_rotation_during_dispatch_denied_and_anchor_stops_after_revoke(self):
        with self.vault.key_lock(self.first, shared=True):
            self.assertEqual(self.command("rotate-key", self.first), (1, "", "PROCESS_ALREADY_RUNNING"))
            self.assertEqual(self.command("revoke-key", self.first), (1, "", "PROCESS_ALREADY_RUNNING"))
        self.assertEqual(self.command("revoke-key", self.first), (0, "REVOKED", ""))
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_policy_key(**self.scope)

    def test_restart_and_sftp_rotation_preserve_scope_and_probe(self):
        restart = self.vault.import_restart_ssh(OTHER, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        extended = Policy([{**policy().targets[TARGET].value, "capabilities": ["host.probe", "docker.restart"],
                            "restart_secret_ref": restart}])
        self.policy.return_value = extended
        scope = dict(anchor=restart, scope_digest=extended.targets[TARGET].scope_digest, purpose="docker.restart",
                     target=TARGET, policy_revision=1, consumer_uid=WORKER_UID)
        self.assertEqual(self.command("rotate-key", restart, purpose="docker.restart"), (0, OTHER + ":v2", ""))
        self.assertEqual(self.vault.use_policy_key(**scope), self.key)
        self.assertEqual(self.vault.use_policy_key(**(scope | {"purpose": "host.probe", "anchor": self.first})), private_key())
        with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
            self.vault.use_restart_ssh(restart, worker_uid=WORKER_UID, target=TARGET, policy_revision=1)
        target = BackupTarget.parse({**destination(), "id": OTHER, "secret_ref": ACTOR + ":v1", "policy_revision": 1})
        backup = self.vault.import_backup_ssh(ACTOR, 1, private_key(), owner_id=ACTOR, broker_uid=os.geteuid(), target=OTHER)
        scope = dict(anchor=backup, scope_digest=target.digest, purpose="backup.sftp", target=OTHER,
                     policy_revision=1, consumer_uid=os.geteuid())
        with patch.object(BackupTarget, "load", return_value=target):
            self.assertEqual(self.command("rotate-key", backup, purpose="backup.sftp", target=OTHER), (0, ACTOR + ":v2", ""))
            self.assertEqual(self.vault.use_policy_key(**scope), self.key)
            with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
                self.vault.use_policy_key(**(scope | {"consumer_uid": WORKER_UID}))
            self.assertEqual(self.command("revoke-key", ACTOR + ":v2", target=OTHER, purpose="backup.sftp"), (0, "REVOKED", ""))
            with self.assertRaisesRegex(Denied, "SECRET_NOT_ACTIVE"):
                self.vault.use_policy_key(**scope)

    def test_racing_rotations_commit_one_lifecycle_event(self):
        def rotate(_):
            try:
                return self.vault.change_key(self.first, key=self.key, **self.scope)
            except Denied as error:
                return error.code
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(rotate, range(2)))
            self.assertEqual(results.count(SECRET + ":v2"), 1)
            self.assertTrue(set(results) <= {SECRET + ":v2", "SECRET_SCOPE_DENIED", "PROCESS_ALREADY_RUNNING"})
        with self.vault.journal.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM secret_lifecycle").fetchone()[0], 1)
