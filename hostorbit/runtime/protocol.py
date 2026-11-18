"""Canonical bounded frames shared by local IPC and signed capabilities."""

from datetime import datetime
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


def docker_summary(value, *, include_ports=None, include_mounts=None, include_network=None, include_dependencies=None, include_started_at=None):
    fields(value, ("status", "containers"))
    status, rows = value["status"], value["containers"]
    if (status not in ("OBSERVED", "NOT_CONFIGURED", "POLICY_INVALID", "UNAVAILABLE")
            or not isinstance(rows, list) or len(rows) > 8 or bool(rows) != (status == "OBSERVED")):
        raise Denied("PROBE_DOCKER_INVALID")
    names = ("id", "project", "service", "state")
    if include_ports is None:
        # Stored observations and Worker receipts can contain older wire formats.
        include_ports = bool(rows and isinstance(rows[0], dict) and "published_ports" in rows[0])
    if include_ports:
        names += ("published_ports",)
    if include_mounts is None:
        include_mounts = bool(rows and isinstance(rows[0], dict) and "mount_status" in rows[0])
    if include_mounts:
        if not include_ports:
            raise Denied("PROBE_DOCKER_INVALID")
        names += ("mount_status",)
    if include_network is None:
        include_network = bool(rows and isinstance(rows[0], dict) and "network_status" in rows[0])
    if include_network:
        if not include_mounts:
            raise Denied("PROBE_DOCKER_INVALID")
        names += ("network_status",)
    if include_dependencies is None:
        include_dependencies = bool(rows and isinstance(rows[0], dict) and "dependency_status" in rows[0])
    if include_dependencies:
        if not include_network:
            raise Denied("PROBE_DOCKER_INVALID")
        names += ("dependency_status",)
    if include_started_at is None:
        include_started_at = bool(rows and isinstance(rows[0], dict) and "started_at" in rows[0])
    if include_started_at:
        if not include_dependencies:
            raise Denied("PROBE_DOCKER_INVALID")
        names += ("started_at",)
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
        if include_mounts and (item["mount_status"] not in ("NONE", "PRESENT", "UNKNOWN")
                               or item["state"] != "RUNNING" and item["mount_status"] != "UNKNOWN"):
            raise Denied("PROBE_DOCKER_INVALID")
        if include_network and (item["network_status"] not in ("ISOLATED", "OTHER", "UNKNOWN")
                                or item["state"] != "RUNNING" and item["network_status"] != "UNKNOWN"):
            raise Denied("PROBE_DOCKER_INVALID")
        if include_dependencies and (
            item["dependency_status"] not in ("ISOLATED", "OTHER", "UNKNOWN")
            or (item["mount_status"] != "NONE" or item["network_status"] != "ISOLATED")
            and item["dependency_status"] != "UNKNOWN"
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        if include_started_at and item["started_at"] is not None:
            started_at = item["started_at"]
            if (item["state"] != "RUNNING" or not isinstance(started_at, str)
                    or started_at.startswith("0001-01-01T00:00:00")
                    or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", started_at)):
                raise Denied("PROBE_DOCKER_INVALID")
            try:
                datetime.fromisoformat(started_at)
            except ValueError:
                raise Denied("PROBE_DOCKER_INVALID") from None
    return value
