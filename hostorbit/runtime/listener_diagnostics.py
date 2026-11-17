"""Report local TCP listeners for one port in the current Linux network namespace."""

import argparse
from ipaddress import ip_address
import json
from pathlib import Path
import re
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


def inspect_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="List local TCP bind addresses for one port")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect_port(args.port)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report))
    return int(any(report[family]["state"] == "UNKNOWN" for family in ("ipv4", "ipv6")))


if __name__ == "__main__":
    raise SystemExit(main())
