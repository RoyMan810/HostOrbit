"""Root-provisioned single SFTP destination; never selected by Web/Worker input."""

from dataclasses import dataclass
from pathlib import PurePosixPath

import asyncssh

from ..errors import Denied
from .policy import Target
from .protocol import ULID, checksum, decode, fields, integer, text
from .storage import protected_bytes


@dataclass(frozen=True)
class BackupTarget:
    value: dict

    @classmethod
    def parse(cls, value):
        if isinstance(value, dict) and value == {"v": 1, "enabled": False} and type(value["v"]) is int and value["enabled"] is False:
            return None
        fields(value, ("v", "enabled", "id", "ip", "port", "allowed_cidrs", "host_key", "username", "directory", "secret_ref", "policy_revision"))
        if type(value["v"]) is not int or value["v"] != 1 or value["enabled"] is not True:
            raise Denied("BACKUP_TARGET_INVALID")
        # Reuse the numeric IP/CIDR/metadata-address protections. This does not
        # add SFTP to the managed VPS capability registry.
        Target.parse({**{k: value[k] for k in ("id", "ip", "port", "allowed_cidrs", "host_key", "secret_ref", "policy_revision")},
                      "dependencies": [], "capabilities": ["host.probe"]})
        text(value["username"], r"[a-z_][a-z0-9_-]{0,31}", "BACKUP_TARGET_INVALID")
        path = text(value["directory"], r"/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}/)*[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}", "BACKUP_TARGET_INVALID")
        if len(path) > 512 or str(PurePosixPath(path)) != path or any(p in {".", ".."} for p in PurePosixPath(path).parts):
            raise Denied("BACKUP_TARGET_INVALID")
        try:
            key = asyncssh.import_public_key(value["host_key"])
            if key.get_algorithm() != "ssh-ed25519":
                raise ValueError()
        except (ValueError, asyncssh.KeyImportError):
            raise Denied("BACKUP_TARGET_INVALID") from None
        return cls(value)

    @classmethod
    def load(cls, path, *, owner=0):
        return cls.parse(decode(protected_bytes(path, owner=owner), canonical_required=False))

    @property
    def digest(self):
        return checksum(self.value)
