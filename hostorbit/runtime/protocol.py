"""Canonical bounded frames shared by local IPC and signed capabilities."""

import hashlib
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
