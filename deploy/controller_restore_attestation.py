"""Sign and verify the Owner's recovery evidence for one migration backup."""

import argparse
import base64
import hashlib
from pathlib import Path
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from deploy.artifact import ArtifactError, read_at
from deploy.build_update_release import signer_from_file
from hostorbit.errors import Denied
from hostorbit.runtime.protocol import SHA256, ULID, canonical, decode, fields, integer, text


KIND = "hostorbit.controller-migration-restore"
MAX_EVIDENCE = 1024 * 1024
MAX_AGE = 1800
CHECKS = ("restored_in_isolation", "sqlite_audit_verified", "owner_login_verified", "independent_storage_verified")


def validate_claims(claims):
    fields(claims, ("v", "type", "source_instance", "snapshot_id", "marker_sha256", "schema",
                    "tested_at", "checks", "evidence_sha256"))
    integer(claims["v"], 1, 1)
    if claims["type"] != KIND:
        raise Denied("CONTROLLER_RESTORE_ATTESTATION_INVALID")
    for name in ("source_instance", "snapshot_id"):
        text(claims[name], ULID)
    for name in ("marker_sha256", "evidence_sha256"):
        text(claims[name], SHA256)
    integer(claims["schema"], 1, 2**31 - 1)
    integer(claims["tested_at"], 1, 253402300799)
    if any(value is not True for value in fields(claims["checks"], CHECKS).values()):
        raise Denied("CONTROLLER_RESTORE_CHECK_MISSING")


def evidence_digest(evidence):
    if not 0 < len(evidence) <= MAX_EVIDENCE:
        raise Denied("CONTROLLER_RESTORE_EVIDENCE_SIZE")
    return hashlib.sha256(evidence).hexdigest()


def sign_restore(claims, evidence, signer):
    if not isinstance(claims, dict) or "evidence_sha256" in claims:
        raise Denied("CONTROLLER_RESTORE_ATTESTATION_INVALID")
    claims = {**claims, "evidence_sha256": evidence_digest(evidence)}
    validate_claims(claims)
    return canonical({"claims": claims,
                      "signature": base64.b64encode(signer.sign(canonical(claims)).signature).decode("ascii")})


def verify_restore(record, evidence, owner_key, *, backup, now, controller_key, release_key):
    if owner_key in (controller_key, release_key):
        raise Denied("CONTROLLER_RESTORE_SEPARATE_OWNER_KEY_REQUIRED")
    try:
        envelope = fields(decode(record), ("claims", "signature"))
        claims = envelope["claims"]
        validate_claims(claims)
        VerifyKey(owner_key).verify(canonical(claims), base64.b64decode(envelope["signature"], validate=True))
    except (BadSignatureError, ValueError, TypeError) as error:
        raise Denied("CONTROLLER_RESTORE_ATTESTATION_INVALID") from error
    if any(claims[claim] != backup[field] for claim, field in (
            ("source_instance", "source_instance"), ("snapshot_id", "snapshot_id"),
            ("marker_sha256", "marker_sha256"), ("schema", "source_schema"))):
        raise Denied("CONTROLLER_RESTORE_ATTESTATION_SCOPE_MISMATCH")
    integer(now, 1, 253402300799)
    if not 0 <= now - claims["tested_at"] <= MAX_AGE:
        raise Denied("CONTROLLER_RESTORE_ATTESTATION_STALE")
    if evidence_digest(evidence) != claims["evidence_sha256"]:
        raise Denied("CONTROLLER_RESTORE_EVIDENCE_CHANGED")
    return {"status": "OWNER_RESTORE_ATTESTATION_VERIFIED", "tested_at": claims["tested_at"],
            "evidence_sha256": claims["evidence_sha256"], "attestation_sha256": hashlib.sha256(record).hexdigest(),
            "owner_key_sha256": hashlib.sha256(owner_key).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        claims = decode(read_at(args.claims.parent, args.claims.name, 16384), canonical_required=False)
        evidence = read_at(args.evidence.parent, args.evidence.name, MAX_EVIDENCE)
        sys.stdout.buffer.write(sign_restore(claims, evidence, signer_from_file(args.signing_key)))
    except (Denied, ArtifactError, OSError) as error:
        code = error.code if isinstance(error, Denied) else "CONTROLLER_RESTORE_SIGNING_FAILED"
        print(f"HostOrbit: {code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
