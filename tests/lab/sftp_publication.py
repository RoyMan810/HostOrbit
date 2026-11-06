"""Exercise Stage 0 publication against an isolated OpenSSH SFTP receiver."""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
from platform import freedesktop_os_release
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from nacl.secret import Aead
from nacl.signing import SigningKey

from stage0.journal import connect_journal
from stage0.recovery import SignedBackup, accept_bundle, issue_request, prepare_bundle
from stage0.snapshot import BackupDenied, BackupLab, Phase, Work, secret_context


_FILES = ("ciphertext.age", "envelope.json", "signature")


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.stderr.strip()})")
    return result.stdout


def age_key(path):
    command("age-keygen", "-o", path)
    return command("age-keygen", "-y", path).strip()


class SftpFailure(RuntimeError):
    def __init__(self, phase, stderr):
        self.phase = phase
        super().__init__(f"SFTP {phase} failed ({stderr.strip()})")


class SftpPublication:
    def __init__(self, account, port, identity, known_hosts):
        self.command = [
            "/usr/bin/sftp", "-F", "/dev/null", "-b", "-", "-P", str(port), "-i", str(identity),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=6",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null", f"{account}@127.0.0.1",
        ]

    def _batch(self, phase, commands, *, cwd=None):
        result = subprocess.run(
            self.command, input="\n".join(commands) + "\n", cwd=cwd,
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode:
            raise SftpFailure(phase, result.stderr)

    @staticmethod
    def _destination(backup_id):
        if not re.fullmatch(r"[0-9a-f]{32}", backup_id):
            raise ValueError("Expected a generated backup ID")
        return f"/store/{backup_id}"

    def _download(self, remote):
        with TemporaryDirectory() as directory:
            self._batch("readback", [f"get {remote}/{name} {name}" for name in _FILES], cwd=directory)
            return SignedBackup(*(Path(directory, name).read_bytes() for name in _FILES))

    def publish(self, backup_id, backup):
        final = self._destination(backup_id)
        staging = final + ".partial"
        with TemporaryDirectory() as directory:
            payloads = (backup.ciphertext, backup.envelope, backup.signature)
            for name, payload in zip(_FILES, payloads, strict=True):
                Path(directory, name).write_bytes(payload)
            self._batch(
                "upload",
                [f"mkdir {staging}", *(f"put {name} {staging}/{name}" for name in _FILES)],
                cwd=directory,
            )
        received = self._download(staging)
        if received != backup:
            raise BackupDenied("SFTP_READBACK_MISMATCH")
        self._batch("publish", [f"rename {staging} {final}"])
        return received.envelope_sha256

    def fetch(self, backup_id):
        return self._download(self._destination(backup_id))


@contextmanager
def listen(config, log, *, limit=None, before_session=None):
    """Provide accepted sockets to the real sshd in inetd mode."""
    stop = Event()
    with closing(socket.socket()) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(0.1)
        port = server.getsockname()[1]

        def serve():
            count = 0
            with log.open("ab") as errors:
                while not stop.is_set():
                    try:
                        stream, _ = server.accept()
                    except TimeoutError:
                        continue
                    count += 1
                    with stream:
                        if count == limit:
                            server.close()
                        if before_session is not None:
                            before_session(count)
                        child = subprocess.Popen(
                            ["/usr/sbin/sshd", "-i", "-e", "-f", str(config)],
                            stdin=stream, stdout=stream, stderr=errors,
                        )
                    try:
                        child.wait(timeout=20)
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=5)
                    if count == limit:
                        return

        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(serve)
            try:
                yield port
            finally:
                stop.set()
                task.result(timeout=25)


class SftpPublicationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="hostorbit-sftp-", dir="/run")))
        self.root.chmod(0o711)
        self.account = f"ho-sftp-{secrets.token_hex(4)}"
        # Ubuntu's shadow entry '*' disables password login and allows public-key auth without PAM.
        command(
            "/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/store",
            "--no-create-home", "--shell", "/bin/sh", "--password", "*", self.account,
        )
        self.addCleanup(command, "/usr/sbin/userdel", self.account)
        user = pwd.getpwnam(self.account)
        jail = self.root / "jail"
        jail.mkdir(mode=0o755)
        jail.chmod(0o755)
        self.store = jail / "store"
        self.store.mkdir(mode=0o700)
        os.chown(self.store, user.pw_uid, user.pw_gid)

        for key in ("host", "client"):
            command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.root / key)
        authorized = self.root / "authorized_keys"
        authorized.write_text("restrict " + (self.root / "client.pub").read_text(), encoding="ascii")
        authorized.chmod(0o644)
        self.config = self.root / "sshd_config"
        self.config.write_text(
            f"HostKey {self.root / 'host'}\n"
            f"AuthorizedKeysFile {authorized}\n"
            f"AllowUsers {self.account}\n"
            f"ChrootDirectory {jail}\n"
            "UsePAM no\nPermitRootLogin no\nPermitTTY no\nPermitUserRC no\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "AuthenticationMethods publickey\nPubkeyAuthentication yes\nDisableForwarding yes\n"
            "Subsystem sftp internal-sftp\nForceCommand internal-sftp -d /store\n",
            encoding="ascii",
        )
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        command("/usr/sbin/sshd", "-t", "-f", self.config)

        self.controller = self.root / "controller"
        self.controller.mkdir(mode=0o700)
        self.lab = BackupLab.create(self.controller, secrets.token_bytes(Aead.KEY_SIZE))
        self.owner = self.root / "owner.agekey"
        self.recipient = age_key(self.owner)
        self.signer = SigningKey.generate()
        self.values = {"old": b"old-generation", "current": b"new-generation"}
        for name, value in self.values.items():
            self.lab.finish_rotation(self.lab.admit(Work.ROTATION), name, value)

    @contextmanager
    def endpoint(self, **kwargs):
        log = self.root / "sshd.log"
        try:
            with listen(self.config, log, **kwargs) as port:
                host_key = (self.root / "host.pub").read_text(encoding="ascii").split()[:2]
                known_hosts = self.root / "known_hosts"
                known_hosts.write_text(f"[127.0.0.1]:{port} {' '.join(host_key)}\n", encoding="ascii")
                yield SftpPublication(self.account, port, self.root / "client", known_hosts)
        except Exception:
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise

    def run_backup(self, endpoint):
        return self.lab.run(self.recipient, self.signer, endpoint.publish)

    def phase(self):
        with connect_journal(self.controller / "controller.sqlite3") as db:
            return db.execute("SELECT phase FROM backups").fetchone()[0]

    def assert_failed_without_publication(self):
        self.assertEqual(self.phase(), Phase.FAILED)
        self.assertEqual(len(list(self.store.glob("*.partial"))), 1)
        self.assertEqual([path for path in self.store.iterdir() if path.suffix != ".partial"], [])
        with connect_journal(self.controller / "controller.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM pins").fetchone()[0], 0)
        self.lab.finish_job(self.lab.admit(Work.JOB))

    def test_sftp_publication_readback_and_restore_after_source_removal(self):
        with self.endpoint() as endpoint:
            backup_id = self.run_backup(endpoint)
            self.assertEqual(self.phase(), Phase.PUBLISHED)
            self.assertEqual([path.name for path in self.store.iterdir()], [backup_id])
            shutil.rmtree(self.controller)
            backup = endpoint.fetch(backup_id)

        target = self.root / "target.agekey"
        age_key(target)
        ledger = self.root / "recovery.sqlite3"
        request = issue_request(
            ledger, target_id="fresh-lab", transport_identity=target,
            source_envelope_sha256=backup.envelope_sha256,
        )
        bundle, review = prepare_bundle(backup, self.signer.verify_key, self.owner, request)
        restored = accept_bundle(ledger, target, bundle, owner_digest=review.bundle_sha256)
        vault = json.loads(restored.deks)
        with closing(sqlite3.connect(":memory:")) as db:
            db.deserialize(restored.database)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            rows = db.execute("SELECT name, version, ciphertext FROM secret_refs").fetchall()
        self.assertEqual(len(vault["keys"]), 2)
        values = {}
        for name, version, ref in rows:
            key = base64.b64decode(vault["keys"][str(version)])
            encrypted = base64.b64decode(vault["ciphertexts"][ref])
            values[name] = Aead(key).decrypt(encrypted, secret_context(name, version))
        self.assertEqual(values, self.values)

    def test_sftp_disconnection_leaves_staging_and_business_admission_open(self):
        connected, resume = Event(), Event()

        def pause(_):
            connected.set()
            if not resume.wait(8):
                raise RuntimeError("Fixture did not release the SFTP connection")

        with self.endpoint(limit=1, before_session=pause) as endpoint:
            with ThreadPoolExecutor(max_workers=1) as pool:
                operation = pool.submit(self.run_backup, endpoint)
                try:
                    self.assertTrue(connected.wait(8))
                    self.assertEqual(self.phase(), Phase.UPLOADING)
                    self.lab.finish_job(self.lab.admit(Work.JOB))
                finally:
                    resume.set()
                with self.assertRaises(SftpFailure) as failure:
                    operation.result(timeout=25)
        self.assertEqual(failure.exception.phase, "readback")
        self.assert_failed_without_publication()

    def test_sftp_readback_rejects_modified_ciphertext_before_rename(self):
        def tamper(session):
            if session == 2:
                (next(self.store.glob("*.partial")) / "ciphertext.age").write_bytes(b"tampered")

        with self.endpoint(before_session=tamper) as endpoint:
            with self.assertRaisesRegex(BackupDenied, "^SFTP_READBACK_MISMATCH$"):
                self.run_backup(endpoint)
        self.assert_failed_without_publication()


if __name__ == "__main__":
    if sys.argv[1:] != ["--isolated-vm"] or os.geteuid() != 0:
        raise SystemExit("Run as root in a disposable Ubuntu 24.04 VM with --isolated-vm.")
    release = freedesktop_os_release()
    if (release["ID"], release["VERSION_ID"]) != ("ubuntu", "24.04"):
        raise SystemExit("The SFTP fixture requires Ubuntu 24.04.")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
