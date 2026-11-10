"""Root publication coordinator and a separate purpose-restricted SFTP helper."""

import hashlib
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
from threading import Thread

from ..admission import Admission
from ..database import DataAccess, Store
from ..errors import Denied
from .archive_stream import _exact, parse_manifest
from .backup_target import BackupTarget
from .controller_backup import verify_provenance
from .coordinator import Coordinator
from .protocol import SHA256, ULID, canonical, checksum, decode, fields, integer, text
from .sftp_publication import completion, publication_timeout, publish
from .storage import directory_sync, new_private_file, process_lock, protected_bytes


TARGET_PATH = Path("/etc/hostorbit/backup-target.json")
MAX_ARCHIVE = 4 * 1024**3


def receive_and_publish(config, snapshot_id, incoming):
    """Broker UID only in runtime CLI; stdin contains signed encrypted data."""
    target = BackupTarget.load(TARGET_PATH)
    if target is None:
        raise Denied("BACKUP_TARGET_DISABLED")
    length, = struct.unpack("!I", _exact(incoming, 4))
    integer(length, 1, 16384)
    header = fields(decode(_exact(incoming, length)), ("v", "snapshot_id", "target_digest", "envelope"))
    if type(header["v"]) is not int or header["v"] != 1 or header["snapshot_id"] != snapshot_id or header["target_digest"] != target.digest:
        raise Denied("PUBLICATION_BINDING_INVALID")
    size = header["envelope"]["claims"]["ciphertext_size"]
    integer(size, 200, MAX_ARCHIVE)
    parent = Path(config["broker_directory"]) / "upload-staging"
    if not parent.exists():
        parent.mkdir(mode=0o700)
        directory_sync(parent.parent)
    from .pins import _private_directory
    _private_directory(parent)
    if shutil.disk_usage(parent).free < size + 8 * 1024 * 1024:
        raise Denied("PUBLICATION_SPACE_INSUFFICIENT")
    directory = parent / (text(snapshot_id, ULID) + "-" + os.urandom(8).hex())
    directory.mkdir(mode=0o700)
    directory_sync(parent)
    ciphertext = directory / "controller.age"
    try:
        fd = os.open(ciphertext, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            left = size
            while left:
                data = incoming.read(min(left, 65536))
                if not data:
                    raise Denied("PUBLICATION_INPUT_TRUNCATED")
                left -= len(data)
                output.write(data)
            if incoming.read(1):
                raise Denied("PUBLICATION_INPUT_TRAILING_DATA")
            output.flush()
            os.fsync(output.fileno())
        trusted = protected_bytes(config["public_verify_key"], owner=0, maximum=32)
        claims = verify_provenance(ciphertext, header["envelope"], trusted)
        if claims["manifest"]["snapshot_id"] != snapshot_id:
            raise Denied("PUBLICATION_BINDING_INVALID")
        from .vault import Vault
        credential = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "broker-dek"
        vault = Vault(config["vault_directory"], credential, systemd_credential=True)

        def key():
            current = BackupTarget.load(TARGET_PATH)
            if current is None or current.digest != target.digest:
                raise Denied("SFTP_TARGET_CHANGED")
            return vault.use_backup_ssh(target.value["secret_ref"], broker_uid=config["broker_uid"],
                                        target=target.value["id"], policy_revision=target.value["policy_revision"])

        return publish(target, snapshot_id, ciphertext, claims, canonical(header["envelope"]), key)
    finally:
        # Local encrypted staging only. Never delete remote partial/final data.
        shutil.rmtree(directory)
        directory_sync(parent)


def _feed(directory, snapshot_id, target, envelope, stream, owner):
    value = canonical({"v": 1, "snapshot_id": snapshot_id, "target_digest": target.digest, "envelope": envelope})
    integer(len(value), 1, 16384)
    stream.write(struct.pack("!I", len(value)) + value)
    path = directory / "controller.age"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        import stat
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o777 != 0o600
                or info.st_nlink != 1 or info.st_size != envelope["claims"]["ciphertext_size"]):
            raise Denied("PUBLICATION_SOURCE_CHANGED")
        with os.fdopen(fd, "rb", closefd=False) as source:
            while data := source.read(65536):
                stream.write(data)
    finally:
        os.close(fd)
    stream.flush()


def run_with_systemd(config, directory, snapshot_id, target, envelope):
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    unit = "hostorbit-publish-" + snapshot_id.lower()
    timeout = publication_timeout(envelope["claims"]["ciphertext_size"]) + 30
    args = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit,
            "--property=User=" + str(config["broker_uid"]), "--property=Group=" + str(config["broker_gid"]),
            "--property=LoadCredentialEncrypted=broker-dek:" + config["vault_credential"],
            "--property=RuntimeMaxSec=" + str(timeout) + "s", "--property=TimeoutStopSec=1s", "--property=KillMode=control-group",
            "--property=UMask=0077", "--property=LimitCORE=0", "--property=MemoryMax=512M",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=RestrictSUIDSGID=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
            "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "--property=ReadWritePaths=" + config["broker_directory"] + " " + config["vault_directory"],
            "--property=Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1",
            "/opt/hostorbit/venv/bin/hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json", "publish-controller", "--snapshot-id", snapshot_id]
    errors, result, diagnostics = [], bytearray(), bytearray()
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def send():
        try:
            _feed(directory, snapshot_id, target, envelope, process.stdin, 0)
        except BaseException as error:
            errors.append(error)
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def read(stream, retained):
        while data := stream.read(4096):
            if len(retained) < 16385:
                retained.extend(data[:16385 - len(retained)])

    threads = [Thread(target=send, daemon=True), Thread(target=read, args=(process.stdout, result), daemon=True),
               Thread(target=read, args=(process.stderr, diagnostics), daemon=True)]
    try:
        for thread in threads:
            thread.start()
        code = process.wait(timeout=timeout + 5)
        for thread in threads:
            thread.join(2)
        if code or errors or any(thread.is_alive() for thread in threads):
            allowed = {b"SFTP_HOST_KEY_MISMATCH", b"SFTP_AUTHENTICATION_FAILED", b"SFTP_PERSISTENCE_UNSUPPORTED",
                       b"SFTP_CONNECTION_LOST", b"SFTP_TIMEOUT", b"SFTP_REMOTE_FAILED", b"SFTP_CONNECTION_FAILED",
                       b"SFTP_NETWORK_OR_STORAGE_UNAVAILABLE", b"SFTP_READBACK_MISMATCH", b"SFTP_FINAL_INCOMPLETE",
                       b"SFTP_DIRECTORY_UNTRUSTED", b"SFTP_TARGET_CHANGED", b"SECRET_NOT_ACTIVE", b"SECRET_SCOPE_DENIED",
                       b"PUBLICATION_SPACE_INSUFFICIENT", b"PUBLICATION_BINDING_INVALID", b"ARCHIVE_PROVENANCE_INVALID"}
            for line in bytes(diagnostics).splitlines():
                if line in allowed:
                    raise Denied(line.decode("ascii"), 503)
            raise Denied("PUBLICATION_HELPER_FAILED", 503)
        return decode(bytes(result), canonical_required=False)
    except subprocess.TimeoutExpired:
        raise Denied("PUBLICATION_HELPER_TIMEOUT", 503) from None
    finally:
        try:
            subprocess.run(["/usr/bin/systemctl", "stop", unit + ".service"], capture_output=True, timeout=2,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(2)
            for thread in threads:
                if thread.ident is not None:
                    thread.join(2)


class Publisher:
    def __init__(self, config, *, target_path=TARGET_PATH, owner=0, runner=run_with_systemd):
        self.config, self.target_path, self.owner, self.runner = config, target_path, owner, runner
        self.admission = Admission(config["writer_directory"], owner=owner)
        self.coordinator = Coordinator(Path(config["supervisor_directory"]) / "snapshots", self.admission)

    def _record(self, snapshot_id, phase, reason=None):
        try:
            self.coordinator._transition(snapshot_id, phase, reason)
        except BaseException:
            self.admission.publish("RECOVERY_HOLD", snapshot_id)
            raise

    def publish(self, snapshot_id):
        if os.geteuid() != self.owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        text(snapshot_id, ULID)
        target = BackupTarget.load(self.target_path, owner=self.owner)
        if target is None:
            raise Denied("BACKUP_TARGET_DISABLED")
        directory = self.coordinator.directory / "captures" / snapshot_id
        from .pins import _private_directory
        _private_directory(directory)
        envelope = parse_manifest(protected_bytes(directory / "provenance.json", owner=self.owner, maximum=16384, exact_mode=0o600))
        trusted = protected_bytes(self.config["public_verify_key"], owner=self.owner, maximum=32)
        claims = verify_provenance(directory / "controller.age", envelope, trusted)
        if claims["manifest"]["snapshot_id"] != snapshot_id:
            raise Denied("PUBLICATION_BINDING_INVALID")
        expected = completion(target, snapshot_id, claims, canonical(envelope))
        expected_receipt = {**expected, "marker_sha256": checksum(expected),
                            "remote_path": target.value["directory"] + "/" + snapshot_id, "verified": True}
        with process_lock(self.coordinator.directory / "publication.lock"):
            request = directory / "publication-request.json"
            if request.exists():
                if parse_manifest(protected_bytes(request, owner=self.owner, maximum=16384, exact_mode=0o600)) != expected:
                    raise Denied("PUBLICATION_TARGET_OR_SOURCE_CHANGED")
            else:
                try:
                    new_private_file(request, canonical(expected))
                except BaseException:
                    self.admission.publish("RECOVERY_HOLD", snapshot_id)
                    raise
            try:
                with self.coordinator.journal.connect() as db:
                    row = db.execute("SELECT phase FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
                if row is None or row["phase"] not in {"SIGNED", "FAILED", "UPLOADING", "PUBLISHED"}:
                    raise Denied("PUBLICATION_STAGE_INVALID")
                if row["phase"] != "PUBLISHED":
                    if row["phase"] != "UPLOADING":
                        self._record(snapshot_id, "UPLOADING")
                receipt = self.runner(self.config, directory, snapshot_id, target, envelope)
                if receipt != expected_receipt:
                    raise Denied("PUBLICATION_RECEIPT_INVALID")
                path = directory / "publication-receipt.json"
                if path.exists():
                    if parse_manifest(protected_bytes(path, owner=self.owner, maximum=16384, exact_mode=0o600)) != receipt:
                        raise Denied("PUBLICATION_RECEIPT_INVALID")
                else:
                    new_private_file(path, canonical(receipt))
                store = Store(self.config["database"], access=DataAccess(self.config["app_uid"], self.config.get("app_gid")), writers=self.admission)
                with store.write(kind="control") as db:
                    if not db.execute("SELECT 1 FROM audit WHERE event='backup.published' AND correlation_id=?", (snapshot_id,)).fetchone():
                        import time
                        store.event(db, at=int(time.time()), actor="local-owner-cli", kind="backup.published", target=target.value["id"],
                                    outcome="SUCCEEDED", correlation=snapshot_id, details={"ciphertext_sha256": expected["ciphertext_sha256"], "target_digest": target.digest})
                if row["phase"] != "PUBLISHED":
                    self._record(snapshot_id, "PUBLISHED")
                return {"snapshot_id": snapshot_id, "status": "PUBLISHED", "target_id": target.value["id"],
                        "remote_path": receipt["remote_path"], "remote_verified": True, "off_host": True,
                        "failure_domain_verified": False, "restore_verified": False, "backup_gate": "DENIED"}
            except BaseException:
                try:
                    with self.coordinator.journal.connect() as db:
                        row = db.execute("SELECT phase FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
                    if row is not None and row["phase"] in {"UPLOADING", "PUBLISHED"}:
                        self._record(snapshot_id, "FAILED", "PUBLICATION_NOT_CONFIRMED")
                except BaseException:
                    self.admission.publish("RECOVERY_HOLD", snapshot_id)
                    raise
                raise
