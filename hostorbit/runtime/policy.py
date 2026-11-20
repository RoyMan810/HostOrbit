"""Protected, fixed-capability targets. General DNS/URL registration is not exposed."""

from dataclasses import dataclass
import base64
import hashlib
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
CAPABILITIES = {"host.probe": Capability(False, "vps:probe"), "docker.restart": Capability(True, "vps:restart")}


@dataclass(frozen=True)
class Target:
    value: dict

    @classmethod
    def parse(cls, value):
        base = ("id", "ip", "port", "allowed_cidrs", "host_key", "secret_ref", "policy_revision", "dependencies", "capabilities")
        extended = isinstance(value, dict) and "restart_secret_ref" in value
        fields(value, base + (("restart_secret_ref",) if extended else ()))
        text(value["id"], ULID)
        text(value["secret_ref"], ULID + r":v[1-9][0-9]{0,8}")
        integer(value["port"], 1, 65535)
        integer(value["policy_revision"], 1, 2**31 - 1)
        try:
            address = ipaddress.ip_address(value["ip"])
            if (str(address) != value["ip"] or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
                    or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None) or "%" in value["ip"]):
                raise ValueError
            if not isinstance(value["allowed_cidrs"], list) or not 1 <= len(value["allowed_cidrs"]) <= 16:
                raise ValueError
            networks = [ipaddress.ip_network(cidr, strict=True) for cidr in value["allowed_cidrs"]]
            if not any(address in net for net in networks) or str(address) in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"):
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
        if ("docker.restart" in value["capabilities"]) != extended:
            raise Denied("CAPABILITY_DISABLED")
        if extended:
            text(value["restart_secret_ref"], ULID + r":v[1-9][0-9]{0,8}")
            if value["restart_secret_ref"].split(":")[0] == value["secret_ref"].split(":")[0]:
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
        if len(self.targets) != len(values):
            raise Denied("TARGET_POLICY_INVALID")

    @classmethod
    def load(cls, path, *, owner=0):
        value = decode(protected_bytes(path, owner=owner), canonical_required=False)
        fields(value, ("v", "targets"))
        if type(value["v"]) is not int or value["v"] != 1 or not isinstance(value["targets"], list):
            raise Denied("TARGET_POLICY_INVALID")
        return cls(value["targets"])

    def enrollment_catalog(self, *, ssh_endpoints=False):
        catalog = {}
        for target in self.targets.values():
            if "host.probe" in target.value["capabilities"]:
                key = base64.b64decode(target.value["host_key"].split()[1], validate=True)
                digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
                catalog[target.id] = {"fingerprint": "SHA256:" + digest, "scope_digest": target.scope_digest,
                                      "policy_revision": target.revision}
                if ssh_endpoints:
                    catalog[target.id].update({field: target.value[field] for field in ("ip", "port", "host_key")})
        return catalog

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
