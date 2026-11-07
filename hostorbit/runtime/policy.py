"""Protected, fixed-capability targets. General DNS/URL registration is not exposed."""

from dataclasses import dataclass
import base64
import ipaddress
import re

from ..errors import Denied
from .protocol import SHA256, ULID, checksum, decode, fields, integer, text
from .storage import protected_bytes


@dataclass(frozen=True)
class Capability:
    mutating: bool
    permission: str


# New adapters enter this registry only after their preconditions/effect bounds are implemented.
CAPABILITIES = {"host.probe": Capability(False, "vps:probe")}


@dataclass(frozen=True)
class Target:
    value: dict

    @classmethod
    def parse(cls, value):
        fields(value, ("id", "ip", "port", "allowed_cidrs", "host_key", "secret_ref", "policy_revision", "dependencies", "capabilities"))
        text(value["id"], ULID)
        text(value["secret_ref"], ULID + r":v[1-9][0-9]{0,8}")
        integer(value["port"], 1, 65535)
        integer(value["policy_revision"], 1, 2**31 - 1)
        try:
            address = ipaddress.ip_address(value["ip"])
            if str(address) != value["ip"] or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or "%" in value["ip"]:
                raise ValueError
            if not isinstance(value["allowed_cidrs"], list) or not 1 <= len(value["allowed_cidrs"]) <= 16:
                raise ValueError
            networks = [ipaddress.ip_network(cidr, strict=True) for cidr in value["allowed_cidrs"]]
            if not any(address in net for net in networks) or str(address) in ("169.254.169.254", "100.100.100.200"):
                raise ValueError
            host_key = value["host_key"].split()
            if len(host_key) != 2 or host_key[0] != "ssh-ed25519" or len(base64.b64decode(host_key[1], validate=True)) != 51:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise Denied("TARGET_POLICY_INVALID") from None
        if (not isinstance(value["dependencies"], list) or len(value["dependencies"]) > 100
                or any(not isinstance(v, str) or re.fullmatch(r"[a-zA-Z0-9:_-]{1,128}", v) is None for v in value["dependencies"])
                or len(set(value["dependencies"])) != len(value["dependencies"])):
            raise Denied("TARGET_POLICY_INVALID")
        if (not isinstance(value["capabilities"], list) or not value["capabilities"]
                or any(not isinstance(v, str) or v not in CAPABILITIES for v in value["capabilities"])
                or len(set(value["capabilities"])) != len(value["capabilities"])):
            raise Denied("CAPABILITY_DISABLED")
        return cls(value)

    @property
    def id(self):
        return self.value["id"]

    @property
    def scope_digest(self):
        return checksum(self.value)

    @property
    def revision(self):
        return self.value["policy_revision"]


class Policy:
    def __init__(self, targets):
        values = [Target.parse(t) for t in targets]
        self.targets = {t.id: t for t in values}
        if not self.targets or len(self.targets) != len(values):
            raise Denied("TARGET_POLICY_INVALID")

    @classmethod
    def load(cls, path, *, owner=0):
        value = decode(protected_bytes(path, owner=owner), canonical_required=False)
        fields(value, ("v", "targets"))
        if type(value["v"]) is not int or value["v"] != 1 or not isinstance(value["targets"], list):
            raise Denied("TARGET_POLICY_INVALID")
        return cls(value["targets"])

    @property
    def digest(self):
        return checksum([self.targets[k].value for k in sorted(self.targets)])

    def target(self, identity, capability, scope_digest):
        target = self.targets.get(identity)
        if target is None or capability not in target.value["capabilities"] or capability not in CAPABILITIES:
            raise Denied("CAPABILITY_DISABLED")
        if target.scope_digest != scope_digest:
            raise Denied("STALE_SCOPE")
        return target

    def closure(self, identity):
        affected = {identity}
        while True:
            resources = set().union(*(set(self.targets[h].value["dependencies"]) for h in affected))
            next_set = affected | {t.id for t in self.targets.values() if resources.intersection(t.value["dependencies"])}
            if next_set == affected:
                return sorted(affected)
            affected = next_set
