"""Manual retention of registered backups. Only an exact local Controller ciphertext can be released."""

import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..errors import Denied
from .activation import atomic
from .archive_stream import file_record, parse_manifest, private_stream
from .authority import host_binding
from .backup_target import BackupTarget
from .controller_backup import ControllerBackup, verify_provenance_claims
from .pins import _private_directory
from .protocol import ULID, canonical, checksum, fields, text
from .publication import TARGET_PATH, run_with_systemd
from .resource_archive import _check_ciphertext, _claims
from .sftp_publication import completion
from .storage import directory_sync, process_lock, protected_bytes


OWNER_KEY = Path("/etc/hostorbit/retention-owner.pub")


def resource_inventory(directory, anchor, owner):
    """Verify a capture directory. Resource identity and scope reside in the encrypted manifest."""
    directory = Path(directory)
    _private_directory(directory)
    key = protected_bytes(anchor, owner=owner, maximum=32)
    raw = protected_bytes(directory / "volume.provenance.json", owner=owner, exact_mode=0o600)
    claims = _claims(parse_manifest(raw), key)
    with private_stream(directory / "volume.age", owner) as (stream, _):
        _check_ciphertext(stream, claims)
    return {"ciphertext_sha256": claims["ciphertext_sha256"], "application_schema": claims["application_schema"],
            "manifest_sha256": claims["manifest_sha256"], "recipient": claims["recipient"],
            "signing_key_sha256": claims["signing_key_sha256"], "provenance_sha256": hashlib.sha256(raw).hexdigest(),
            "retention": "PROTECTED", "external_publication": "UNVERIFIED"}


@dataclass(frozen=True)
class PublishedCopy:
    directory: Path
    envelope: dict
    receipt: dict
    barrier_sequence: int


class Retention:
    def __init__(self, config, *, owner=0, target_path=TARGET_PATH, owner_key=OWNER_KEY, runner=run_with_systemd):
        if os.geteuid() != owner:
            raise Denied("LOCAL_ROOT_REQUIRED")
        self.config, self.owner, self.target_path, self.owner_key = config, owner, target_path, owner_key
        self.runner = runner
        self.backup = ControllerBackup(config, owner=owner)
        self.snapshots = self.backup.coordinator.directory
        self.key = protected_bytes(config["public_verify_key"], owner=owner, maximum=32)

    def capture(self, snapshot_id):
        base = self.snapshots / "captures"
        directory = base / text(snapshot_id, ULID)
        _private_directory(base)
        _private_directory(directory)
        raw = protected_bytes(directory / "provenance.json", owner=self.owner, exact_mode=0o600)
        envelope = parse_manifest(raw)
        claims = verify_provenance_claims(envelope, self.key)
        if claims["manifest"]["snapshot_id"] != snapshot_id:
            raise Denied("RETENTION_ARCHIVE_MISMATCH")
        return directory, envelope, claims

    def inventory(self):
        with self.backup.coordinator.journal.connect() as db:
            rows = db.execute("SELECT id,phase FROM snapshots ORDER BY id").fetchall()
        entries = []
        for snapshot, phase in rows:
            entry = {"snapshot_id": snapshot, "phase": phase, "retention": "PROTECTED",
                     "external_publication": "UNVERIFIED"}
            if phase == "PUBLISHED":
                entry["external_publication"] = "HISTORICAL_PUBLICATION_ONLY"
            if phase in ("SIGNED", "UPLOADING", "PUBLISHED", "FAILED"):
                try:
                    directory, envelope, claims = self.capture(snapshot)
                    manifest = claims["manifest"]
                    entry.update(ciphertext_sha256=claims["ciphertext_sha256"], source_instance=manifest["source_instance"],
                                 recipient=claims["recipient"], signing_key_sha256=claims["signing_key_sha256"],
                                 pin_sha256=manifest["pin_sha256"], audit_head=manifest["audit_head"],
                                 provenance_sha256=checksum(envelope), schema=manifest["schema"],
                                 local_ciphertext_present=(directory / "controller.age").is_file())
                except (Denied, OSError):
                    entry["source"] = "UNVERIFIED"
            entries.append(entry)
        return entries

    def _recorded(self, snapshot, target):
        directory, envelope, claims = self.capture(snapshot)
        with self.backup.coordinator.journal.connect() as db:
            row = db.execute("SELECT t.seq FROM snapshots s JOIN transitions t ON s.id=t.snapshot_id "
                             "WHERE s.id=? AND s.phase='PUBLISHED' AND t.phase='SHORT_BARRIER'", (snapshot,)).fetchone()
        if row is None:
            raise Denied("RETENTION_PUBLICATION_REQUIRED")
        marker = completion(target, snapshot, claims, canonical(envelope))
        receipt = {**marker, "marker_sha256": checksum(marker), "remote_path": target.value["directory"] + "/" + snapshot,
                   "verified": True}
        for name, expected in (("publication-request.json", marker), ("publication-receipt.json", receipt)):
            if protected_bytes(directory / name, owner=self.owner, exact_mode=0o600) != canonical(expected):
                raise Denied("RETENTION_PUBLICATION_MISMATCH")
        return PublishedCopy(directory, envelope, receipt, row[0])

    def _pin(self, manifest):
        snapshot = manifest["snapshot_id"]
        path = Path(self.config["broker_directory"]) / "snapshot-pins" / snapshot / "pin.json"
        raw = protected_bytes(path, owner=self.config["broker_uid"], exact_mode=0o600, maximum=32 * 1024**2)
        if hashlib.sha256(raw).hexdigest() != manifest["pin_sha256"]:
            raise Denied("RETENTION_PIN_CHANGED")
        pin = parse_manifest(raw)
        if (pin["snapshot_id"] != snapshot or pin["type"] != "vault.pin" or pin["v"] != 1
                or pin["key_generations"] != [1] or set(pin["key_fingerprints"]) != {"1"}):
            raise Denied("RETENTION_PIN_UNSUPPORTED")
        return pin

    def _dependencies(self, previous, replacement):
        old, keep = self._pin(previous), self._pin(replacement)
        if (old["key_fingerprints"] != keep["key_fingerprints"]
                or not {canonical(ref) for ref in old["references"]}.issubset(
                    canonical(ref) for ref in keep["references"])):
            raise Denied("RETENTION_VAULT_DEPENDENCY_PROTECTED")
        gate = self.backup.gate_row()
        if gate["instance_id"] != replacement["source_instance"] or gate["host_binding"] != host_binding():
            raise Denied("RETENTION_SOURCE_CHANGED")
        with self.backup.store.connect(readonly=True) as db:
            db.execute("BEGIN")
            if db.execute("PRAGMA user_version").fetchone()[0] != replacement["schema"]:
                raise Denied("RETENTION_SOURCE_CHANGED")
            if previous["audit_sequence"] > replacement["audit_sequence"]:
                raise Denied("RETENTION_AUDIT_CHECKPOINT_PROTECTED")
            self.backup.store.verify_audit_connection(db)
            for manifest in (previous, replacement):
                seq = manifest["audit_sequence"]
                row = db.execute("SELECT digest FROM audit WHERE seq=?", (seq,)).fetchone()
                checkpoint = row[0] if row else None
                if seq == 0:
                    checkpoint = "0" * 64
                if checkpoint != manifest["audit_head"]:
                    raise Denied("RETENTION_AUDIT_CHECKPOINT_PROTECTED")

    def _review(self, snapshot, keep, evidence):
        if snapshot == keep:
            raise Denied("RETENTION_LAST_COPY_PROTECTED")
        target = BackupTarget.load(self.target_path, owner=self.owner)
        if target is None:
            raise Denied("BACKUP_TARGET_DISABLED")
        old, retained = self._recorded(snapshot, target), self._recorded(keep, target)
        first, second = old.envelope["claims"], retained.envelope["claims"]
        if (retained.barrier_sequence <= old.barrier_sequence or first["ciphertext_sha256"] == second["ciphertext_sha256"]
                or first["recipient"] != second["recipient"]
                or any(first["manifest"][k] != second["manifest"][k] for k in ("source_instance", "schema"))):
            raise Denied("RETENTION_REPLACEMENT_INCOMPATIBLE")
        self._dependencies(first["manifest"], second["manifest"])
        raw = protected_bytes(evidence, owner=self.owner, maximum=1024 * 1024, private=True)
        if not raw:
            raise Denied("RETENTION_EVIDENCE_REQUIRED")
        claims = {"v": 1, "type": "hostorbit.retire-local-controller-ciphertext",
                  "source_instance": second["manifest"]["source_instance"], "target_digest": target.digest,
                  "release_snapshot": snapshot, "release_marker_sha256": old.receipt["marker_sha256"],
                  "keep_snapshot": keep, "keep_marker_sha256": retained.receipt["marker_sha256"],
                  "keep_restore_and_independent_storage_confirmed": True, "local_retention_and_dependencies_reviewed": True,
                  "evidence_sha256": hashlib.sha256(raw).hexdigest()}
        return claims, target, old, retained

    def review(self, snapshot, keep, evidence):
        claims, *_ = self._review(snapshot, keep, evidence)
        return claims

    def retire(self, snapshot, keep, evidence, approval):
        with process_lock(self.snapshots / "archive.lock"), process_lock(self.snapshots / "publication.lock"):
            expected, target, old, retained = self._review(snapshot, keep, evidence)
            raw = protected_bytes(approval, owner=self.owner, private=True)
            signed = fields(parse_manifest(raw), ("claims", "signature"))
            key = protected_bytes(self.owner_key, owner=self.owner, maximum=32)
            if key == self.key or canonical(signed["claims"]) != canonical(expected):
                raise Denied("RETENTION_APPROVAL_INVALID")
            try:
                VerifyKey(key).verify(canonical(expected), base64.b64decode(signed["signature"], validate=True))
            except (TypeError, ValueError, BadSignatureError):
                raise Denied("RETENTION_APPROVAL_INVALID") from None

            path = old.directory / "controller.age"
            intent = old.directory / ("local-retirement-" + checksum(signed) + ".json")
            had_intent = os.path.lexists(intent)
            if had_intent and protected_bytes(intent, owner=self.owner, exact_mode=0o600) != raw:
                raise Denied("RETENTION_INTENT_CHANGED")
            if had_intent and not os.path.lexists(path):
                directory_sync(old.directory)
                return {"status": "LOCAL_CIPHERTEXT_RETIRED", "snapshot_id": snapshot}
            for candidate, copy in ((snapshot, old), (keep, retained)):
                record = file_record(copy.directory / "controller.age", "controller.age", self.owner)
                if record["sha256"] != copy.receipt["ciphertext_sha256"] or record["size"] != copy.receipt["ciphertext_size"]:
                    raise Denied("RETENTION_ARCHIVE_MISMATCH")
                remote = self.runner(self.config, copy.directory, candidate, target, copy.envelope, verify_only=True)
                if canonical(remote) != canonical(copy.receipt):
                    raise Denied("RETENTION_PUBLICATION_MISMATCH")
            # No remote waits inside the writer barrier. Recheck currency after both readbacks.
            with self.backup.admission.writer():
                final, *_ = self._review(snapshot, keep, evidence)
                if canonical(final) != canonical(expected):
                    raise Denied("RETENTION_APPROVAL_INVALID")
                if not had_intent:
                    atomic(intent, raw)
                path.unlink()
                directory_sync(old.directory)
            return {"status": "LOCAL_CIPHERTEXT_RETIRED", "snapshot_id": snapshot}
