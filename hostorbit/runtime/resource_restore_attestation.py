"""Verify signed manual restore procedure evidence for Docker named volumes."""

import base64
import hashlib

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..errors import Denied
from .archive_stream import AGE_PATH
from .protocol import SHA256, canonical, decode, fields, integer, text
from .resource_archive import _NAME, verify_archive


_RESOURCE_TYPE = "docker.named-volume"
_MAX_AGE = 90 * 86400
_MAX_EVIDENCE = 1024 * 1024
_CHECKS = ("new_empty_target", "data_and_metadata", "application_check", "occupied_target_refused")


def verify_attestation(record, evidence, owner_key, *, application_schema, procedure_sha256, now):
    """Verify the Owner's signed statement against caller-pinned scope and time."""
    try:
        integer(now, 0, 253402300799)
        text(application_schema, _NAME)
        text(procedure_sha256, SHA256)
        envelope = fields(decode(record), ("claims", "signature"))
        claims = fields(envelope["claims"], ("v", "type", "resource_type", "application_schema",
                                             "procedure_sha256", "tested_at", "test_archive_sha256",
                                             "evidence_sha256", "checks"))
        integer(claims["v"], 1, 1)
        tested_at = integer(claims["tested_at"], 0, now)
        text(claims["application_schema"], _NAME)
        for name in ("procedure_sha256", "test_archive_sha256", "evidence_sha256"):
            text(claims[name], SHA256)
        checks = fields(claims["checks"], _CHECKS)
        if (claims["type"] != "hostorbit.resource-restore-attestation"
                or claims["resource_type"] != _RESOURCE_TYPE
                or any(value is not True for value in checks.values())):
            raise Denied("RESTORE_ATTESTATION_INVALID")
        signature = base64.b64decode(envelope["signature"], validate=True)
        VerifyKey(owner_key).verify(canonical(claims), signature)
    except (Denied, BadSignatureError, TypeError, ValueError, AttributeError):
        raise Denied("RESTORE_ATTESTATION_INVALID") from None
    if claims["application_schema"] != application_schema or claims["procedure_sha256"] != procedure_sha256:
        raise Denied("RESTORE_ATTESTATION_SCOPE_MISMATCH")
    expires_at = tested_at + _MAX_AGE
    if now >= expires_at:
        raise Denied("RESTORE_ATTESTATION_EXPIRED")
    if (not isinstance(evidence, bytes) or not 0 < len(evidence) <= _MAX_EVIDENCE
            or hashlib.sha256(evidence).hexdigest() != claims["evidence_sha256"]):
        raise Denied("RESTORE_ATTESTATION_EVIDENCE_CHANGED")
    return {"status": "RESTORE_ATTESTED", "resource_type": _RESOURCE_TYPE, "application_schema": application_schema,
            "procedure_sha256": procedure_sha256, "tested_at": tested_at, "expires_at": expires_at,
            "test_archive_sha256": claims["test_archive_sha256"], "evidence_sha256": claims["evidence_sha256"],
            "restore_eligibility": "NOT_EVALUATED"}


def verify_restore_source(ciphertext, provenance, archive_key, identity, *,
                          attestation, evidence, owner_key, application_schema, procedure_sha256, now,
                          age_path=AGE_PATH, tool_owner=0):
    """Verify an archive and its procedure evidence without checking a target."""
    if archive_key == owner_key:
        raise Denied("RESTORE_ATTESTATION_SEPARATE_OWNER_KEY_REQUIRED")
    procedure = verify_attestation(attestation, evidence, owner_key, application_schema=application_schema,
                                   procedure_sha256=procedure_sha256, now=now)
    archive = verify_archive(ciphertext, provenance, archive_key, identity,
                             application_schema=application_schema, now=now, age_path=age_path, tool_owner=tool_owner)
    return {"archive": archive, "procedure": procedure, "restore_eligibility": "NOT_EVALUATED"}
