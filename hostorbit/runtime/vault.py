"""Broker-only immutable SSH key versions with AEAD-bound protected policy."""

import hashlib
import json
import os
from pathlib import Path
import re

from nacl.exceptions import CryptoError
from nacl.secret import Aead

from ..errors import Denied
from .protocol import ULID, canonical, checksum, integer, text
from .storage import Journal, new_private_file, protected_bytes, systemd_credential_bytes


_SCHEMA = """
CREATE TABLE secrets(ref TEXT PRIMARY KEY, metadata TEXT NOT NULL, object_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')));
"""


class Vault:
    def __init__(self, directory, key_path, *, systemd_credential=False, writers=None):
        self.directory = Path(directory)
        self.journal = Journal(self.directory / "vault.sqlite3", writers=writers)
        key = (systemd_credential_bytes(key_path, owner=os.geteuid()) if systemd_credential else
               protected_bytes(key_path, owner=os.geteuid(), maximum=32, private=True))
        if len(key) != Aead.KEY_SIZE:
            raise Denied("VAULT_KEY_INVALID")
        self._aead = Aead(key)

    @classmethod
    def initialize(cls, directory, key_path, *, systemd_credential=False):
        directory = Path(directory)
        vault = cls(directory, key_path, systemd_credential=systemd_credential)
        Journal.initialize(directory / "vault.sqlite3", _SCHEMA)
        (directory / "objects").mkdir(mode=0o700)
        return vault

    def import_ssh(self, secret_id, version, key, *, owner_id, worker_uid, target):
        """Local administrative provisioning; never registered as a Web or Worker RPC."""
        return self._import_ssh(secret_id, version, key, owner_id=owner_id, consumer_uid=worker_uid,
                                target=target, purpose="host.probe", policy_revision=1)

    def import_backup_ssh(self, secret_id, version, key, *, owner_id, broker_uid, target, policy_revision=1):
        """Separate Broker-only SFTP purpose, not a managed VPS probe identity."""
        return self._import_ssh(secret_id, version, key, owner_id=owner_id, consumer_uid=broker_uid,
                                target=target, purpose="backup.sftp", policy_revision=policy_revision)

    def _import_ssh(self, secret_id, version, key, *, owner_id, consumer_uid, target, purpose, policy_revision):
        for value in (secret_id, owner_id, target):
            text(value, ULID)
        integer(version, 1, 10**9 - 1)
        integer(consumer_uid, 1, 2**31 - 1)
        integer(policy_revision, 1, 2**31 - 1)
        if (not isinstance(key, bytes) or not 100 <= len(key) <= 8192
                or not key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
                or not key.endswith(b"-----END OPENSSH PRIVATE KEY-----\n")):
            raise Denied("SSH_KEY_FORMAT_UNSUPPORTED")
        from .ssh import validate_private_key
        validate_private_key(key)
        reference = f"{secret_id}:v{version}"
        metadata = {"secret_id": secret_id, "version": version, "kind": "ssh.ed25519", "purpose": purpose,
                    "owner_id": owner_id, "allowed_consumers": [consumer_uid], "allowed_consumers_digest": checksum([consumer_uid]), "target": target,
                    "state": "ACTIVE", "policy_revision": policy_revision, "key_version": 1}
        ciphertext = bytes(self._aead.encrypt(key, canonical(metadata)))
        object_digest = hashlib.sha256(ciphertext).hexdigest()
        with self.journal.write(kind="business") as db:
            if db.execute("SELECT 1 FROM secrets WHERE ref=?", (reference,)).fetchone():
                raise Denied("SECRET_VERSION_IMMUTABLE", 409)
            new_private_file(self.directory / "objects" / object_digest, ciphertext)
            db.execute("INSERT INTO secrets VALUES(?,?,?,'ACTIVE')", (reference, canonical(metadata).decode(), object_digest))
        return reference

    def use_ssh(self, reference, *, worker_uid, target):
        return self._use_ssh(reference, consumer_uid=worker_uid, target=target, purpose="host.probe")

    def use_backup_ssh(self, reference, *, broker_uid, target, policy_revision):
        return self._use_ssh(reference, consumer_uid=broker_uid, target=target, purpose="backup.sftp", policy_revision=policy_revision)

    def _use_ssh(self, reference, *, consumer_uid, target, purpose, policy_revision=None):
        text(reference, ULID + r":v[1-9][0-9]{0,8}")
        with self.journal.connect() as db:
            row = db.execute("SELECT * FROM secrets WHERE ref=?", (reference,)).fetchone()
            if row is None or row["state"] != "ACTIVE":
                raise Denied("SECRET_NOT_ACTIVE")
            metadata = json.loads(row["metadata"])
            if (reference != f'{metadata["secret_id"]}:v{metadata["version"]}' or metadata["kind"] != "ssh.ed25519"
                    or metadata["key_version"] != 1 or metadata["allowed_consumers_digest"] != checksum(metadata["allowed_consumers"])
                    or metadata["purpose"] != purpose or metadata["target"] != target
                    or consumer_uid not in metadata["allowed_consumers"] or metadata["state"] != "ACTIVE"
                    or (policy_revision is not None and metadata["policy_revision"] != policy_revision)):
                raise Denied("SECRET_SCOPE_DENIED")
            digest = text(row["object_digest"], r"[0-9a-f]{64}")
            ciphertext = protected_bytes(self.directory / "objects" / digest, owner=os.geteuid(), maximum=9000, exact_mode=0o600)
            if hashlib.sha256(ciphertext).hexdigest() != digest:
                raise Denied("VAULT_OBJECT_CORRUPT")
            try:
                return self._aead.decrypt(ciphertext, canonical(metadata))
            except CryptoError:
                raise Denied("VAULT_POLICY_OR_OBJECT_CORRUPT") from None

    def revoke(self, reference):
        with self.journal.write(kind="business") as db:
            if db.execute("UPDATE secrets SET state='REVOKED' WHERE ref=? AND state='ACTIVE'", (reference,)).rowcount != 1:
                raise Denied("SECRET_NOT_ACTIVE")
