"""Canonical bounded frames shared by local IPC and signed capabilities."""

import hashlib
from ipaddress import ip_address
import json
import re

from ..errors import Denied


MAX_FRAME = 16384
ULID = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
SHA256 = r"[0-9a-f]{64}"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def checksum(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field")
        obj[key] = value
    return obj


def decode(data, *, canonical_required=True):
    def depth(value, level=0):
        if level > 12:
            raise ValueError("nested frame")
        if isinstance(value, dict):
            for v in value.values():
                depth(v, level + 1)
        elif isinstance(value, list):
            for v in value:
                depth(v, level + 1)
    try:
        if not data or len(data) > MAX_FRAME:
            raise ValueError("frame length")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
        depth(value)
        if canonical_required and canonical(value) != data:
            raise ValueError("non-canonical frame")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise Denied("RPC_INVALID_REQUEST") from None


def fields(value, names):
    if not isinstance(value, dict) or value.keys() != set(names):
        raise Denied("RPC_INVALID_REQUEST")
    return value


def text(value, pattern, code="RPC_INVALID_REQUEST"):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise Denied(code)
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Denied("RPC_INVALID_REQUEST")
    return value


def software_summary(value):
    fields(value, ("docker", "nginx"))
    if any(state not in ("PRESENT", "NOT_DETECTED", "UNKNOWN") for state in value.values()):
        raise Denied("PROBE_SOFTWARE_INVALID")
    return value


def _validate_published_ports(ports, state):
    if ports is None:
        return
    if state in ("UNKNOWN", "NOT_FOUND") or not isinstance(ports, list) or len(ports) > 8:
        raise Denied("PROBE_DOCKER_INVALID")
    seen = set()
    for port in ports:
        fields(port, ("address", "host_port", "container_port", "protocol"))
        address = text(port["address"], r"[0-9a-f:.]{2,45}")
        try:
            if str(ip_address(address)) != address:
                raise ValueError("noncanonical address")
        except ValueError:
            raise Denied("PROBE_DOCKER_INVALID") from None
        host = integer(port["host_port"], 1, 65535)
        private = integer(port["container_port"], 1, 65535)
        protocol = port["protocol"]
        if protocol not in ("tcp", "udp", "sctp") or (address, host, private, protocol) in seen:
            raise Denied("PROBE_DOCKER_INVALID")
        seen.add((address, host, private, protocol))


def docker_summary(value, *, include_ports=None):
    fields(value, ("status", "containers"))
    status, rows = value["status"], value["containers"]
    if (status not in ("OBSERVED", "NOT_CONFIGURED", "POLICY_INVALID", "UNAVAILABLE")
            or not isinstance(rows, list) or len(rows) > 8 or bool(rows) != (status == "OBSERVED")):
        raise Denied("PROBE_DOCKER_INVALID")
    names = ("id", "project", "service", "state")
    if include_ports is None:
        # Stored observations and Worker receipts support both wire generations.
        include_ports = bool(rows and isinstance(rows[0], dict) and "published_ports" in rows[0])
    if include_ports:
        names += ("published_ports",)
    seen = set()
    for item in rows:
        fields(item, names)
        identity = text(item["id"], r"[0-9a-f]{64}")
        text(item["project"], r"[a-z0-9][a-z0-9_-]{0,62}")
        text(item["service"], r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
        if identity in seen or item["state"] not in (
            "CREATED", "RESTARTING", "RUNNING", "REMOVING", "PAUSED", "EXITED", "DEAD", "UNKNOWN", "NOT_FOUND",
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        seen.add(identity)
        if include_ports:
            _validate_published_ports(item["published_ports"], item["state"])
    return value
