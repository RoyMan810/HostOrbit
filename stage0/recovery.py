"""T0-3 recovery transport for small fixtures. It never imports live state."""

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .journal import connect_journal, reserve_journal


_SOURCE_FORMAT = "hostorbit.stage0.source.v1"
_RECOVERY_FORMAT = "hostorbit.stage0.recovery.v1"
_MAX_PART = 1024 * 1024
_MAX_BUNDLE = 3 * _MAX_PART
_MAX_ENVELOPE = 16 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TARGET_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_AGE_RECIPIENT = re.compile(r"age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}")


class Rejected(RuntimeError):
    """A lab recovery step failed verification."""


@dataclass(frozen=True)
class Snapshot:
    database: bytes = field(repr=False)
    deks: bytes = field(repr=False)

    def objects(self) -> dict[str, bytes]:
        return {"database": self.database, "deks": self.deks}

    def manifest(self) -> dict:
        return {
            name: {"sha256": _sha256(data), "size": len(data)}
            for name, data in self.objects().items()
        }

    def encoded(self) -> dict[str, str]:
        objects = self.objects()
        if any(not 0 < len(data) <= _MAX_PART for data in objects.values()):
            raise Rejected("SNAPSHOT_SIZE")
        return {name: base64.b64encode(data).decode("ascii") for name, data in objects.items()}


@dataclass(frozen=True)
class SignedBackup:
    ciphertext: bytes = field(repr=False)
    envelope: bytes
    signature: bytes

    @property
    def envelope_sha256(self) -> str:
        return _sha256(self.envelope)


@dataclass(frozen=True)
class RecoveryRequest:
    target_id: str
    recipient: str
    challenge: str
    expires_at: int
    source_envelope_sha256: str

    def binding(self) -> dict:
        if (
            not _TARGET_ID.fullmatch(self.target_id)
            or not _DIGEST.fullmatch(self.challenge)
            or not _DIGEST.fullmatch(self.source_envelope_sha256)
            or type(self.expires_at) is not int
        ):
            raise Rejected("INVALID_REQUEST")
        return {
            "target_id": self.target_id,
            "recipient_fingerprint": _fingerprint(self.recipient),
            "challenge": self.challenge,
            "expires_at": self.expires_at,
            "source_envelope_sha256": self.source_envelope_sha256,
        }


@dataclass(frozen=True)
class OwnerReview:
    bundle_sha256: str
    request: RecoveryRequest
    manifest: dict

    @property
    def recipient_fingerprint(self) -> str:
        return _fingerprint(self.request.recipient)


def _now() -> int:
    return int(time.time())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _object(raw: bytes, fields: set[str]) -> dict:
    try:
        value = json.loads(raw)
        if isinstance(value, dict) and value.keys() == fields and _canonical(value) == raw:
            return value
    except (ValueError, UnicodeError, RecursionError):
        pass
    raise Rejected("INVALID_FORMAT")


def _decode_snapshot(encoded) -> Snapshot:
    if not isinstance(encoded, dict) or encoded.keys() != {"database", "deks"}:
        raise Rejected("INVALID_SNAPSHOT")
    try:
        objects = {name: base64.b64decode(data, validate=True) for name, data in encoded.items()}
    except (binascii.Error, ValueError, TypeError):
        raise Rejected("INVALID_SNAPSHOT") from None
    if any(not 0 < len(data) <= _MAX_PART for data in objects.values()):
        raise Rejected("SNAPSHOT_SIZE")
    return Snapshot(**objects)


def _fingerprint(recipient: str) -> str:
    if not _AGE_RECIPIENT.fullmatch(recipient):
        raise Rejected("X25519_RECIPIENT_REQUIRED")
    return _sha256(recipient.encode("ascii"))


def _run_age(arguments: list[str], data: bytes) -> bytes:
    try:
        result = subprocess.run(
            arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise Rejected("AGE_COMMAND_FAILED") from None
    return result.stdout


def _recipient(identity: Path) -> str:
    recipient = _run_age(["age-keygen", "-y", str(identity.absolute())], b"").decode("ascii")
    return recipient.strip()


def _encrypt(recipient: str, plaintext: bytes) -> bytes:
    _fingerprint(recipient)
    return _run_age(["age", "-r", recipient], plaintext)


def _decrypt(identity: Path, ciphertext: bytes) -> bytes:
    return _run_age(["age", "-d", "-i", str(identity.absolute())], ciphertext)


def seal_source(snapshot: Snapshot, recipient: str, signing_key: SigningKey) -> SignedBackup:
    ciphertext = _encrypt(recipient, _canonical(snapshot.encoded()))
    envelope = _canonical({
        "format": _SOURCE_FORMAT,
        "ciphertext_sha256": _sha256(ciphertext),
        "manifest": snapshot.manifest(),
    })
    return SignedBackup(ciphertext, envelope, signing_key.sign(envelope).signature)


def _verify_source(
    backup: SignedBackup, trusted_signer: VerifyKey, offline_identity: Path,
) -> Snapshot:
    if len(backup.envelope) > _MAX_ENVELOPE or len(backup.ciphertext) > _MAX_BUNDLE:
        raise Rejected("BACKUP_SIZE")
    try:
        trusted_signer.verify(backup.envelope, backup.signature)
    except (BadSignatureError, ValueError):
        raise Rejected("SOURCE_SIGNATURE") from None
    envelope = _object(backup.envelope, {"format", "ciphertext_sha256", "manifest"})
    if envelope["format"] != _SOURCE_FORMAT or envelope["ciphertext_sha256"] != _sha256(backup.ciphertext):
        raise Rejected("SOURCE_CIPHERTEXT")
    _fingerprint(_recipient(offline_identity))
    plaintext = _decrypt(offline_identity, backup.ciphertext)
    snapshot = _decode_snapshot(_object(plaintext, {"database", "deks"}))
    if _canonical(snapshot.manifest()) != _canonical(envelope["manifest"]):
        raise Rejected("SOURCE_MANIFEST")
    return snapshot


def prepare_bundle(
    backup: SignedBackup, trusted_signer: VerifyKey, offline_identity: Path, request: RecoveryRequest,
) -> tuple[bytes, OwnerReview]:
    """Run on the fixture workstation. Send only ciphertext to the target."""
    binding = request.binding()
    if request.expires_at <= _now():
        raise Rejected("REQUEST_EXPIRED")
    if request.source_envelope_sha256 != backup.envelope_sha256:
        raise Rejected("WRONG_SOURCE")
    snapshot = _verify_source(backup, trusted_signer, offline_identity)
    bundle = _encrypt(request.recipient, _canonical({
        "format": _RECOVERY_FORMAT, "binding": binding, "snapshot": snapshot.encoded(),
    }))
    return bundle, OwnerReview(_sha256(bundle), request, snapshot.manifest())


def issue_request(
    ledger: Path, *, target_id: str, transport_identity: Path, source_envelope_sha256: str,
    lifetime_seconds: int = 300,
) -> RecoveryRequest:
    """Persist a single challenge for a fresh target transport identity."""
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 900:
        raise ValueError("Fixture lifetime must be between 1 and 900 seconds")
    request = RecoveryRequest(
        target_id, _recipient(transport_identity), secrets.token_hex(32),
        _now() + lifetime_seconds, source_envelope_sha256,
    )
    binding = _canonical(request.binding())
    reserve_journal(ledger)
    with connect_journal(ledger, initialize=True) as db:
        db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE request (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                binding BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL CHECK (consumed IN (0, 1))
            );
            PRAGMA user_version = 1;
        """)
        db.execute("INSERT INTO request VALUES (1, ?, ?, 0)", (binding, request.expires_at))
        db.execute("COMMIT")
    return request


def accept_bundle(
    ledger: Path, transport_identity: Path, bundle: bytes, *, owner_digest: str,
) -> Snapshot:
    """Accept a digest from the trusted fixture caller, separately from the bundle."""
    if not isinstance(owner_digest, str) or not _DIGEST.fullmatch(owner_digest):
        raise Rejected("OWNER_DIGEST_REQUIRED")
    if not 0 < len(bundle) <= _MAX_BUNDLE:
        raise Rejected("BUNDLE_SIZE")
    if not hmac.compare_digest(owner_digest, _sha256(bundle)):
        raise Rejected("OWNER_DIGEST_MISMATCH")

    with connect_journal(ledger) as db:
        request = db.execute("SELECT binding, expires_at, consumed FROM request WHERE id = 1").fetchone()
        if request is None:
            raise Rejected("MISSING_REQUEST")
        if request["consumed"]:
            raise Rejected("REQUEST_CONSUMED")
        if request["expires_at"] <= _now():
            raise Rejected("REQUEST_EXPIRED")
        binding = json.loads(request["binding"])
        if binding["recipient_fingerprint"] != _fingerprint(_recipient(transport_identity)):
            raise Rejected("WRONG_RECIPIENT")

        raw = _decrypt(transport_identity, bundle)
        payload = _object(raw, {"format", "binding", "snapshot"})
        if payload["format"] != _RECOVERY_FORMAT or _canonical(payload["binding"]) != request["binding"]:
            raise Rejected("WRONG_BINDING")
        snapshot = _decode_snapshot(payload["snapshot"])
        db.execute("BEGIN IMMEDIATE")
        now = _now()
        if request["expires_at"] <= now:
            raise Rejected("REQUEST_EXPIRED")
        result = db.execute(
            "UPDATE request SET consumed = 1 WHERE id = 1 AND binding = ? AND consumed = 0",
            (request["binding"],),
        )
        if result.rowcount != 1:
            raise Rejected("REQUEST_CONSUMED")
        db.execute("COMMIT")
        return snapshot
