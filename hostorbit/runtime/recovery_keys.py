"""Broker-UID recovery provisioning and public credential facts, not secret RPC."""

import hashlib
import os

from nacl.exceptions import CryptoError

from ..errors import Denied
from .pins import _metadata
from .protocol import canonical
from .ssh import validate_private_key
from .storage import protected_bytes


def recovery_only(config, writers):
    if (os.geteuid() != config["broker_uid"] or writers is None
            or writers.state()["phase"] != "READ_ONLY_RECOVERY"):
        raise Denied("RECOVERY_KEY_PROVISIONING_DENIED")


def fingerprint(vault, reference, target):
    with vault.journal.connect() as db:
        row = db.execute("SELECT * FROM secrets WHERE ref=?", (reference,)).fetchone()
        if row is None:
            raise Denied("RECOVERY_KEY_MISSING")
        metadata = _metadata(row)
        if metadata["target"] != target or metadata["purpose"] != "host.probe":
            raise Denied("RECOVERY_KEY_SCOPE_INVALID")
        encrypted = protected_bytes(vault.directory / "objects" / row["object_digest"], owner=os.geteuid(), maximum=9000, exact_mode=0o600)
        if hashlib.sha256(encrypted).hexdigest() != row["object_digest"]:
            raise Denied("VAULT_OBJECT_CORRUPT")
        try:
            key = vault._aead.decrypt(encrypted, canonical(metadata))
        except CryptoError:
            raise Denied("VAULT_POLICY_OR_OBJECT_CORRUPT") from None
        public = validate_private_key(key).get_fingerprint("sha256")
        del key
        return public, row["state"], metadata


def key_facts(vault, old_policy, candidate, worker_uid):
    # Recovery integrity includes every retained version, not just keys selected
    # for activation. No plaintext is returned or serialized.
    with vault.journal.connect() as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
            raise Denied("RECOVERY_VAULT_INVALID")
        for row in db.execute("SELECT * FROM secrets"):
            metadata = _metadata(row)
            raw = protected_bytes(vault.directory / "objects" / row["object_digest"], owner=os.geteuid(), maximum=9000, exact_mode=0o600)
            if hashlib.sha256(raw).hexdigest() != row["object_digest"]:
                raise Denied("RECOVERY_VAULT_INVALID")
            try:
                secret = vault._aead.decrypt(raw, canonical(metadata))
            except CryptoError:
                raise Denied("RECOVERY_VAULT_INVALID") from None
            del secret
    if set(old_policy.targets) != set(candidate.targets):
        raise Denied("RECOVERY_INVENTORY_CHANGED")
    facts = {}
    for identity, old in old_policy.targets.items():
        new = candidate.targets[identity]
        if new.value == old.value:
            continue
        if (any(new.value[k] != old.value[k] for k in old.value if k not in {"secret_ref", "policy_revision"})
                or new.revision != old.revision + 1 or new.value["secret_ref"] == old.value["secret_ref"]):
            raise Denied("RECOVERY_POLICY_SCOPE_CHANGED")
        old_fp, old_state, _ = fingerprint(vault, old.value["secret_ref"], identity)
        new_fp, new_state, metadata = fingerprint(vault, new.value["secret_ref"], identity)
        if (old_state != "REVOKED" or new_state != "ACTIVE" or old_fp == new_fp
                or metadata["allowed_consumers"] != [worker_uid] or metadata["policy_revision"] != new.revision):
            raise Denied("RECOVERY_CREDENTIAL_ROTATION_REQUIRED")
        facts[identity] = {"old_ref": old.value["secret_ref"], "new_ref": new.value["secret_ref"],
                           "old_key_sha256": old_fp, "new_key_sha256": new_fp}
    return facts


def provision(vault, policy, args, config):
    if args.command == "recovery-import-key":
        old = policy.targets.get(args.target)
        if old is None or args.policy_revision != old.revision + 1:
            raise Denied("RECOVERY_POLICY_SCOPE_CHANGED")
        key = protected_bytes(args.key_file, owner=config["broker_uid"], maximum=8192, private=True)
        return vault._import_ssh(args.secret_id, args.version, key, owner_id=args.owner_id, consumer_uid=config["worker_uid"],
                                 target=args.target, purpose="host.probe", policy_revision=args.policy_revision, write_kind="control")
    old = policy.targets.get(args.target)
    if old is None:
        raise Denied("RECOVERY_KEY_SCOPE_INVALID")
    fingerprint(vault, old.value["secret_ref"], args.target)
    with vault.journal.write(kind="control") as db:
        db.execute("UPDATE secrets SET state='REVOKED' WHERE ref=?", (old.value["secret_ref"],))
    return "REVOKED"
