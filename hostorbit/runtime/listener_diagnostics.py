"""Diagnose one TCP port locally or from the host running an explicit probe."""

import argparse
import errno
from ipaddress import ip_address
import json
from pathlib import Path
import re
import socket
import sys


_ROW = re.compile(rb"\s*\d+: ([0-9A-F]{8}|[0-9A-F]{32}):([0-9A-F]{4})\s+\S+\s+([0-9A-F]{2})(?:\s|$)")


def _read_bindings(stream, port, version):
    header = next(stream, b"").split()
    if header[:2] != [b"sl", b"local_address"] or header[3:4] != [b"st"]:
        raise ValueError("Invalid TCP table header")
    width = 8 if version == 4 else 32
    addresses = set()
    for line in stream:
        row = _ROW.match(line)
        if row is None or len(row[1]) != width:
            raise ValueError("Invalid TCP table row")
        if row[3] == b"0A" and int(row[2], 16) == port:
            address = row[1]
            # Linux renders each 32-bit word in host byte order, including IPv6.
            packed = b"".join(int(address[offset:offset + 8], 16).to_bytes(4, sys.byteorder)
                              for offset in range(0, width, 8))
            addresses.add(ip_address(packed))
    return [str(address) for address in sorted(addresses)]


def _validate_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")


def inspect_port(port):
    _validate_port(port)
    report = {"port": port, "protocol": "tcp", "scope": "CURRENT_NETWORK_NAMESPACE", "external_reachability": "NOT_TESTED"}
    for version, filename in ((4, "tcp"), (6, "tcp6")):
        try:
            with Path("/proc/self/net", filename).open("rb") as stream:
                addresses = _read_bindings(stream, port, version)
            state = "LISTENING" if addresses else "NOT_LISTENING"
        except (OSError, ValueError):
            addresses, state = [], "UNKNOWN"
        report[f"ipv{version}"] = {"state": state, "addresses": addresses}
    return report


def probe_port(destination, port):
    _validate_port(port)
    address = ip_address(destination)
    if address.version == 6:
        if address.scope_id is not None or address.is_link_local:
            raise ValueError("IPv6 addresses that require an interface scope are unsupported")
        address = address.ipv4_mapped or address
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("a unicast destination address is required")

    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect((str(address), port))
        state = "CONNECTED"
    except TimeoutError:
        state = "TIMED_OUT"
    except OSError as error:
        state = {errno.ECONNREFUSED: "REFUSED", errno.ENETUNREACH: "UNREACHABLE",
                 errno.EHOSTUNREACH: "UNREACHABLE"}.get(error.errno, "ERROR")
    return {"address": str(address), "port": port, "protocol": "tcp", "scope": "FROM_PROBE_HOST",
            "tcp_reachability": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect a local TCP port or make one TCP connection")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--connect", metavar="IP", help="numeric IPv4 or IPv6 destination")
    args = parser.parse_args(argv)
    try:
        if args.connect is not None:
            report = probe_port(args.connect, args.port)
            ok = report["tcp_reachability"] == "CONNECTED"
        else:
            report = inspect_port(args.port)
            ok = all(report[family]["state"] != "UNKNOWN" for family in ("ipv4", "ipv6"))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report))
    return int(not ok)


if __name__ == "__main__":
    raise SystemExit(main())
