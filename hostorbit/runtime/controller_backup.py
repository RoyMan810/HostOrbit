"""Coherent Controller data capture, one-way age sealing and signed provenance.

The result is local SIGNED storage. It is deliberately not an off-host backup,
restore attestation or authorization for a migration/update.
"""

import base64
from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import resource
import shutil
import sqlite3
import stat
import subprocess
from threading import Thread
import time
from types import SimpleNamespace

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from ..admission import Admission
from ..database import DataAccess, Store
from ..errors import Denied
from .archive_stream import AGE_SHA256, CONTROLLER_FILES, feed, file_record, parse_manifest, recipient, validate_source
from .coordinator import Coordinator
from .pins import _copy_database, _private_directory, capture_with_systemd
from .policy import Policy
from .protocol import canonical, decode, fields
from .storage import Journal, directory_sync, new_private_file, process_lock, protected_bytes


@dataclass(frozen=True)
class Layout:
    app: Path = Path("/opt/hostorbit")
    config: Path = Path("/etc/hostorbit")


def digest_file(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def sign_provenance(manifest, public_recipient, ciphertext, key):
    validate_source(manifest, manifest["snapshot_id"])
    digest, size = digest_file(ciphertext)
    if size < 200:
        raise Denied("ARCHIVE_ENCRYPTION_INCOMPLETE")
    claims = {"v": 1, "type": "hostorbit.controller-backup", "manifest": manifest,
              "recipient": recipient(public_recipient), "ciphertext_sha256": digest, "ciphertext_size": size,
              "age_sha256": AGE_SHA256, "signing_key_sha256": hashlib.sha256(bytes(key.verify_key)).hexdigest()}
    return {"claims": claims, "signature": base64.b64encode(key.sign(canonical(claims)).signature).decode("ascii")}


def verify_provenance(ciphertext, envelope, trusted_key):
    """No secret identity needed: use an independently saved public anchor."""
    fields(envelope, ("claims", "signature"))
    claims = fields(envelope["claims"], ("v", "type", "manifest", "recipient", "ciphertext_sha256", "ciphertext_size",
                                        "age_sha256", "signing_key_sha256"))
    if (type(claims["v"]) is not int or claims["v"] != 1 or claims["type"] != "hostorbit.controller-backup"
            or claims["age_sha256"] != AGE_SHA256 or claims["signing_key_sha256"] != hashlib.sha256(trusted_key).hexdigest()):
        raise Denied("ARCHIVE_PROVENANCE_INVALID")
    try:
        VerifyKey(trusted_key).verify(canonical(claims), base64.b64decode(envelope["signature"], validate=True))
    except (BadSignatureError, ValueError, TypeError):
        raise Denied("ARCHIVE_PROVENANCE_INVALID") from None
    validate_source(claims["manifest"], claims["manifest"]["snapshot_id"])
    recipient(claims["recipient"])
    digest, size = digest_file(ciphertext)
    if digest != claims["ciphertext_sha256"] or size != claims["ciphertext_size"] or size < 200:
        raise Denied("ARCHIVE_CIPHERTEXT_CHANGED")
    return claims


def seal_with_systemd(config, directory, manifest, public_recipient, ciphertext):
    """All remote/crypto waiting happens after Coordinator.snapshot returns."""
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    unit = "hostorbit-seal-" + manifest["snapshot_id"].lower()
    args = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit,
            "--property=User=" + str(config["broker_uid"]), "--property=Group=" + str(config["broker_gid"]),
            "--property=LoadCredentialEncrypted=broker-dek:" + config["vault_credential"],
            "--property=RuntimeMaxSec=140s", "--property=TimeoutStopSec=1s", "--property=KillMode=control-group",
            "--property=UMask=0077", "--property=LimitCORE=0", "--property=MemoryMax=512M",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=RestrictSUIDSGID=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
            "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
            "--property=RestrictAddressFamilies=AF_UNIX", "--property=PrivateNetwork=yes",
            "--property=Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1",
            "/opt/hostorbit/venv/bin/hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json", "seal-controller",
            "--snapshot-id", manifest["snapshot_id"]]
    new_private_file(ciphertext, b"")
    errors, process, feeder = [], None, None
    with Path(ciphertext).open("wb") as output:
        try:
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

            def send():
                try:
                    feed(directory, manifest, public_recipient, process.stdin)
                except BaseException as error:
                    errors.append(error)
                finally:
                    process.stdin.close()

            feeder = Thread(target=send, daemon=True)
            feeder.start()
            code = process.wait(timeout=145)
            feeder.join(timeout=2)
            if code or errors or feeder.is_alive():
                raise Denied("ARCHIVE_SEAL_HELPER_FAILED", 503)
            output.flush()
            os.fsync(output.fileno())
        except subprocess.TimeoutExpired:
            raise Denied("ARCHIVE_SEAL_HELPER_TIMEOUT", 503) from None
        finally:
            try:
                subprocess.run(["/usr/bin/systemctl", "stop", unit + ".service"], capture_output=True, timeout=2,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                if feeder is not None:
                    feeder.join(timeout=2)
    directory_sync(Path(ciphertext).parent)


class ControllerBackup:
    def __init__(self, config, *, layout=Layout(), owner=0, pin=capture_with_systemd, sealer=seal_with_systemd):
        self.config, self.layout, self.owner = config, layout, owner
        self.pin, self.sealer = pin, sealer
        if "writer_directory" not in config:
            raise Denied("WRITER_CONFIGURATION_REQUIRED")
        self.admission = Admission(config["writer_directory"], owner=owner)
        self.coordinator = Coordinator(Path(config["supervisor_directory"]) / "snapshots", self.admission)
        self.store = Store(config["database"], access=DataAccess(config["app_uid"], config.get("app_gid")))
        self.gate = Journal(Path(config["supervisor_directory"]) / "gate.sqlite3")

    def gate_row(self):
        with self.gate.connect() as db:
            row = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
            if row is None:
                raise Denied("ARCHIVE_GATE_UNAVAILABLE")
            return dict(row)

    def drained(self):
        with self.store.read() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 2 and db.execute(
                    "SELECT 1 FROM jobs WHERE claimed_by IS NOT NULL AND status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE') LIMIT 1").fetchone():
                return False
        with self.gate.connect() as db:
            if db.execute("SELECT 1 FROM attempts WHERE state IN ('ISSUED','DISPATCHING') LIMIT 1").fetchone():
                return False
        directory = Path(self.config["broker_directory"])
        info = directory.lstat()
        if info.st_uid != self.config["broker_uid"] or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o777 != 0o700:
            raise Denied("ARCHIVE_BROKER_DIRECTORY_INVALID")
        path = directory / "receipts.sqlite3"
        # Root may read this private Broker DB, but Journal's runtime ownership
        # contract deliberately belongs to Broker, not Root.
        with private_broker_connection(path, self.config["broker_uid"]) as db:
            return db.execute("SELECT 1 FROM receipts WHERE state IN ('PREPARED','DISPATCHING') LIMIT 1").fetchone() is None

    def create(self, public_recipient):
        if os.geteuid() != self.owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        public_recipient = recipient(public_recipient)
        with process_lock(self.coordinator.directory / "archive.lock"):
            baseline = self.gate_row()
            logical = []
            for source in (self.store, self.gate):
                with source.connect() as db:
                    logical.append(db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0])
            for path in (Path(self.config["vault_directory"]) / "vault.sqlite3", Path(self.config["broker_directory"]) / "receipts.sqlite3"):
                with private_broker_connection(path, self.config["broker_uid"]) as db:
                    logical.append(db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0])
                    if path.name == "vault.sqlite3":
                        versions = db.execute("SELECT count(*) FROM secrets").fetchone()[0]
            if any(size > 512 * 1024 * 1024 for size in logical) or versions > 65536:
                raise Denied("ARCHIVE_SIZE_UNSUPPORTED")
            reserve = 2 * (sum(logical) + versions * 9000 + 64 * 1024 * 1024)
            if shutil.disk_usage(self.coordinator.directory).free < reserve:
                raise Denied("ARCHIVE_SPACE_INSUFFICIENT", 503)
            captures = self.coordinator.directory / "captures"
            captures.mkdir(mode=0o700, exist_ok=True)
            _private_directory(captures)
            current = {}

            def capture(snapshot_id):
                current["id"] = snapshot_id
                if not self.drained() or any(self.gate_row()[name] != baseline[name] for name in ("instance_id", "epoch", "policy_digest")):
                    raise Denied("ARCHIVE_DRAIN_OR_EPOCH_CHANGED")
                directory = captures / snapshot_id
                _private_directory(directory, create=True)
                # Reserve the Broker helper budget first, then use the remaining
                # short-barrier time for bounded Controller copies/audit checks.
                pin = self.pin(snapshot_id)
                if pin["snapshot_id"] != snapshot_id or pin["status"] != "LOCAL_PIN_ONLY":
                    raise Denied("ARCHIVE_PIN_INCOMPLETE")
                with self.store.read() as db:
                    schema = db.execute("PRAGMA user_version").fetchone()[0]
                    size = db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
                    if size > 512 * 1024 * 1024:
                        raise Denied("ARCHIVE_SIZE_UNSUPPORTED")
                source = SimpleNamespace(connect=self.store.connect, version=schema)
                check = lambda: self.admission.verify_barrier(snapshot_id)
                _copy_database(source, directory / "app.sqlite3", check)
                _copy_database(self.gate, directory / "gate.sqlite3", check)
                paths = {"runtime.json": self.layout.config / "runtime.json", "targets.json": Path(self.config["targets"]),
                         "gate.pub": Path(self.config["public_verify_key"]), "installation.json": self.layout.app / "installation.json",
                         "release-manifest.json": self.layout.app / "bundle/manifest.json", "release.sig": self.layout.app / "bundle/manifest.sig",
                         "release.pub": self.layout.config / "release-trust.pub", "requirements-install.txt": self.layout.app / "bundle/requirements-install.txt",
                         "sbom.cdx.json": self.layout.app / "bundle/sbom.cdx.json", "compose.json": self.layout.config / "compose.json"}
                for name, path in paths.items():
                    check()
                    new_private_file(directory / name, protected_bytes(path, owner=self.owner, maximum=4 * 1024 * 1024))
                if decode((directory / "runtime.json").read_bytes(), canonical_required=False) != self.config:
                    raise Denied("ARCHIVE_CONFIGURATION_CHANGED")
                policy = Policy.load(directory / "targets.json", owner=self.owner)
                if policy.digest != baseline["policy_digest"]:
                    raise Denied("ARCHIVE_CONFIGURATION_CHANGED")
                pin_path = Path(self.config["broker_directory"]) / "snapshot-pins" / snapshot_id / "pin.json"
                raw_pin = protected_bytes(pin_path, owner=self.config["broker_uid"], maximum=32 * 1024 * 1024, exact_mode=0o600)
                if hashlib.sha256(raw_pin).hexdigest() != pin["manifest_sha256"]:
                    raise Denied("ARCHIVE_PIN_CHANGED")
                pinned_refs = {ref["ref"] for ref in parse_manifest(raw_pin)["references"]}
                if any(target.value["secret_ref"] not in pinned_refs for target in policy.targets.values()):
                    raise Denied("ARCHIVE_REFERENCE_INCOMPLETE")
                with closing(sqlite3.connect((directory / "app.sqlite3").as_uri() + "?mode=ro", uri=True, autocommit=True)) as db:
                    db.row_factory = sqlite3.Row
                    audit_head = Store.verify_audit_connection(db)
                    sequence = db.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0]
                install = parse_manifest((directory / "installation.json").read_bytes())
                release = parse_manifest((directory / "release-manifest.json").read_bytes())
                if install["source_commit"] != release["source_commit"]:
                    raise Denied("ARCHIVE_RELEASE_CHANGED")
                value = {"v": 1, "type": "controller.snapshot", "snapshot_id": snapshot_id,
                         "source_instance": baseline["instance_id"], "gate_epoch": baseline["epoch"], "schema": schema,
                         "audit_head": audit_head, "audit_sequence": sequence,
                         "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "monotonic_ns": time.monotonic_ns(),
                         "captured_utc": int(time.time()), "time_trusted": False, "source_commit": install["source_commit"],
                         "pin_sha256": pin["manifest_sha256"],
                         "files": [file_record(directory / name, name, self.owner) for name in sorted(CONTROLLER_FILES)]}
                validate_source(value, snapshot_id)
                if self.gate_row()["epoch"] != baseline["epoch"]:
                    raise Denied("ARCHIVE_DRAIN_OR_EPOCH_CHANGED")
                new_private_file(directory / "manifest.json", canonical(value))
                check()
                return directory, value

            try:
                snapshot_id, (directory, manifest) = self.coordinator.snapshot(self.drained, capture, metadata={
                    "type": "controller.backup", "baseline_epoch": baseline["epoch"], "source_instance": baseline["instance_id"],
                    "max_drain_seconds": 60, "max_barrier_seconds": 30, "recipient": public_recipient})
                ciphertext = directory / "controller.age"
                self.sealer(self.config, directory, manifest, public_recipient, ciphertext)
                self.coordinator._transition(snapshot_id, "SEALED")
                key = SigningKey(protected_bytes(Path(self.config["supervisor_directory"]) / "signing.key", owner=self.owner,
                                                 maximum=32, exact_mode=0o600))
                if bytes(key.verify_key) != (directory / "gate.pub").read_bytes():
                    raise Denied("ARCHIVE_SIGNING_ANCHOR_CHANGED")
                envelope = sign_provenance(manifest, public_recipient, ciphertext, key)
                verify_provenance(ciphertext, envelope, bytes(key.verify_key))
                new_private_file(directory / "provenance.json", canonical(envelope))
                self.coordinator._transition(snapshot_id, "SIGNED")
                return {"snapshot_id": snapshot_id, "status": "LOCAL_SIGNED_ONLY", "ciphertext": str(ciphertext),
                        "provenance": str(directory / "provenance.json"), "ciphertext_sha256": envelope["claims"]["ciphertext_sha256"],
                        "signing_key_sha256": envelope["claims"]["signing_key_sha256"], "portable_keys_exported": True,
                        "off_host": False, "restore_verified": False, "backup_gate": "DENIED"}
            except BaseException:
                if "id" in current:
                    try:
                        with self.coordinator.journal.connect() as db:
                            phase = db.execute("SELECT phase FROM snapshots WHERE id=?", (current["id"],)).fetchone()[0]
                        if phase in {"BARRIER_RELEASED", "SEALED", "SIGNED"}:
                            self.coordinator._transition(current["id"], "FAILED", "ARCHIVE_NOT_COMPLETED")
                    except BaseException:
                        self.admission.publish("RECOVERY_HOLD", current["id"])
                        raise
                raise


@contextmanager
def private_broker_connection(path, owner):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1):
        raise Denied("ARCHIVE_BROKER_JOURNAL_INVALID")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, autocommit=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        yield db
