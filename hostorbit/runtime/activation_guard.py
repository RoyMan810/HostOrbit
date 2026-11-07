"""Signed host-local activation scope, rechecked at every recovered Gate use."""

import base64
import os

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..errors import Denied
from .archive_stream import parse_manifest
from .protocol import SHA256, ULID, canonical, checksum, fields, text
from .storage import protected_bytes


def authorization(directory, public_key, gate, writers):
    if (not os.path.lexists(directory / "recovery-installation.json")
            and not (writers and os.path.lexists(writers.directory / "recovery-profile.json"))):
        return None  # Existing fresh-install authority contract is unchanged.
    if not gate["activated"]:
        return None
    if writers is None:
        raise Denied("RECOVERY_ACTIVATION_INVALID")
    envelope = fields(parse_manifest(protected_bytes(directory / "activation.json", owner=os.geteuid(), maximum=65536, exact_mode=0o600)),
                      ("claims", "signature"))
    claims = fields(envelope["claims"], ("v", "type", "activation_id", "instance_id", "host_binding", "policy_digest",
        "source_instance", "source_backup_hash", "owner_id", "report_sha256", "allowed_targets", "quarantined_targets", "open_incidents"))
    if (type(claims["v"]) is not int or claims["v"] != 1 or claims["type"] != "hostorbit.recovery-activation"
            or claims["instance_id"] != gate["instance_id"] or claims["host_binding"] != gate["host_binding"]
            or claims["policy_digest"] != gate["policy_digest"] or type(claims["open_incidents"]) is not bool):
        raise Denied("RECOVERY_ACTIVATION_INVALID")
    for name in ("activation_id", "instance_id", "source_instance", "owner_id"):
        text(claims[name], ULID)
    for name in ("host_binding", "policy_digest", "source_backup_hash", "report_sha256"):
        text(claims[name], SHA256)
    for name in ("allowed_targets", "quarantined_targets"):
        values = claims[name]
        if not isinstance(values, list) or len(values) > 100 or any(not isinstance(v, str) for v in values) or values != sorted(set(values)):
            raise Denied("RECOVERY_ACTIVATION_INVALID")
        for value in values:
            text(value, ULID)
    if set(claims["allowed_targets"]) & set(claims["quarantined_targets"]):
        raise Denied("RECOVERY_ACTIVATION_INVALID")
    try:
        VerifyKey(public_key).verify(canonical(claims), base64.b64decode(envelope["signature"], validate=True))
    except (BadSignatureError, ValueError, TypeError):
        raise Denied("RECOVERY_ACTIVATION_INVALID") from None
    if writers.activation_digest() != checksum(envelope):
        raise Denied("RECOVERY_ACTIVATION_INVALID")
    return claims
