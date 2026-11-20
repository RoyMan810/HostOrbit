"""Diagnose one TCP port locally or from the host running an explicit probe."""

import argparse
import errno
from http.client import HTTPException, HTTPResponse
from ipaddress import ip_address
import json
from pathlib import Path
import re
import socket
import ssl
import sys


_ROW = re.compile(rb"\s*\d+: ([0-9A-F]{8}|[0-9A-F]{32}):([0-9A-F]{4})\s+\S+\s+([0-9A-F]{2})(?:\s|$)")

_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")


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


def check_bind(destination, port):
    proposed = ip_address(destination)
    if proposed.version == 6:
        if proposed.scope_id is not None or proposed.is_link_local or proposed.ipv4_mapped is not None:
            raise ValueError("use an unscoped native IPv4 or IPv6 bind address")
    if proposed.is_multicast or str(proposed) == "255.255.255.255":
        raise ValueError("a unicast or wildcard bind address is required")

    report = inspect_port(port)
    candidates = []
    unknown = False
    for version in (4, 6):
        if version == 4 and proposed.version == 6 and not proposed.is_unspecified:
            continue  # Native IPv6 unicast does not overlap an IPv4 listener.
        family = report[f"ipv{version}"]
        unknown |= family["state"] == "UNKNOWN"
        for value in family["addresses"]:
            bound = ip_address(value)
            effective = (bound.ipv4_mapped or bound) if version == 6 else bound
            if effective.version == proposed.version:
                overlaps = proposed == effective or proposed.is_unspecified or effective.is_unspecified
            else:
                # The socket tables do not show whether an IPv6 wildcard is v6-only.
                ipv6 = proposed if proposed.version == 6 else effective
                overlaps = ipv6.is_unspecified
            if overlaps:
                candidates.append(value)
    state = "POSSIBLE_CONFLICT" if candidates else "UNKNOWN" if unknown else "NO_CONFLICT_OBSERVED"
    report["bind_check"] = {"address": str(proposed), "state": state, "candidate_addresses": candidates}
    return report


def _dns_name(name):
    name = name.removesuffix(".")
    labels = name.split(".")
    if len(name) > 253 or labels[-1].isdigit() or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("name must be a DNS name in ASCII or Punycode")
    return name.lower()


def _resolve_addresses(name, expected_ips):
    name = _dns_name(name)
    expected = {ip_address(value) for value in expected_ips}
    if any(getattr(address, "scope_id", None) is not None for address in expected):
        raise ValueError("expected IP addresses must not contain an interface scope")
    report = {"name": name, "scope": "SYSTEM_RESOLVER", "addresses": []}
    try:
        replies = socket.getaddrinfo(name + ".", None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        state = "NO_ADDRESSES" if error.errno in (socket.EAI_NONAME, socket.EAI_NODATA) else "LOOKUP_FAILED"
        return {**report, "state": state}
    addresses = {ip_address(endpoint[0]) for family, _, _, _, endpoint in replies
                 if family in (socket.AF_INET, socket.AF_INET6)}
    if not addresses:
        return {**report, "state": "NO_ADDRESSES"}
    report["addresses"] = _format_addresses(addresses)
    if expected:
        return {**report, "state": "MATCH" if addresses == expected else "MISMATCH",
                "missing_addresses": _format_addresses(expected - addresses),
                "unexpected_addresses": _format_addresses(addresses - expected)}
    return {**report, "state": "RESOLVED"}


def _format_addresses(addresses):
    return [str(address) for address in sorted(addresses, key=lambda address: (address.version, int(address)))]


def _probe_https(secured, name, port, path):
    host = name if port == 443 else f"{name}:{port}"
    request = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    try:
        secured.sendall(request.encode("ascii"))
        with HTTPResponse(secured, method="HEAD") as response:
            response.begin()
            return {"state": "RESPONDED", "status": response.status}
    except TimeoutError:
        return {"state": "TIMED_OUT"}
    except (OSError, HTTPException):
        return {"state": "ERROR"}


def _probe_tls(connection, server_name, port, https_path):
    result = {"server_name": server_name}
    https = {"state": "NOT_TESTED"}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.hostname_checks_common_name = False
        context.load_default_certs()
        with context.wrap_socket(connection, server_hostname=server_name) as secured:
            result["expires_at"] = ssl.cert_time_to_seconds(secured.getpeercert()["notAfter"])
            result["state"] = "VERIFIED"
            if https_path is not None:
                https = _probe_https(secured, server_name, port, https_path)
    except ssl.SSLCertVerificationError:
        result["state"] = "CERTIFICATE_INVALID"
    except TimeoutError:
        result["state"] = "TIMED_OUT"
    except (OSError, ValueError, KeyError):
        result["state"] = "ERROR"
    return result, https


def probe_port(destination, port, *, tls_name=None, https_path=None):
    _validate_port(port)
    if https_path is not None and (
        tls_name is None or not https_path.startswith("/") or https_path.startswith("//")
        or not re.fullmatch(r"[!-~]{1,2048}", https_path) or "#" in https_path
    ):
        raise ValueError("--https-path requires --tls-name and an ASCII path starting with one slash")
    if tls_name is not None:
        tls_name = _dns_name(tls_name)
        tls = {"server_name": tls_name, "state": "NOT_TESTED"}
    https = {"state": "NOT_TESTED"}
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
            if tls_name is not None:
                tls, https = _probe_tls(connection, tls_name, port, https_path)
        state = "CONNECTED"
    except TimeoutError:
        state = "TIMED_OUT"
    except OSError as error:
        state = {errno.ECONNREFUSED: "REFUSED", errno.ENETUNREACH: "UNREACHABLE",
                 errno.EHOSTUNREACH: "UNREACHABLE"}.get(error.errno, "ERROR")
    report = {"address": str(address), "port": port, "protocol": "tcp", "scope": "FROM_PROBE_HOST",
              "tcp_reachability": state}
    if tls_name is not None:
        report["tls"] = tls
    if https_path is not None:
        report["https"] = https
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect TCP listeners, probe TCP/TLS/HTTPS, or resolve a DNS name")
    parser.add_argument("--port", type=int)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-bind", metavar="IP", help="check for overlapping local TCP listeners")
    modes.add_argument("--connect", metavar="IP", help="numeric IPv4 or IPv6 destination")
    modes.add_argument("--resolve", metavar="DNS", help="look up addresses using the system resolver")
    parser.add_argument("--expect-ip", action="append", default=[], metavar="IP", help="expected address; repeat for a set")
    parser.add_argument("--tls-name", metavar="DNS", help="verify the TLS certificate for this DNS name")
    parser.add_argument("--https-path", metavar="PATH", help="send HEAD over the verified TLS connection")
    args = parser.parse_args(argv)
    if args.resolve is not None and args.port is not None:
        parser.error("--resolve does not use --port")
    if args.resolve is None and args.port is None:
        parser.error("--port is required for TCP checks")
    if args.expect_ip and args.resolve is None:
        parser.error("--expect-ip requires --resolve")
    if args.tls_name is not None and args.connect is None:
        parser.error("--tls-name requires --connect")
    if args.https_path is not None and args.tls_name is None:
        parser.error("--https-path requires --tls-name")
    try:
        if args.resolve is not None:
            report = _resolve_addresses(args.resolve, args.expect_ip)
            ok = report["state"] in ("RESOLVED", "MATCH")
        elif args.connect is not None:
            report = probe_port(args.connect, args.port, tls_name=args.tls_name, https_path=args.https_path)
            ok = report["tcp_reachability"] == "CONNECTED"
            if args.tls_name is not None:
                ok = ok and report["tls"]["state"] == "VERIFIED"
            if args.https_path is not None:
                ok = ok and 200 <= report["https"].get("status", 0) < 300
        elif args.check_bind is not None:
            report = check_bind(args.check_bind, args.port)
            ok = report["bind_check"]["state"] == "NO_CONFLICT_OBSERVED"
        else:
            report = inspect_port(args.port)
            ok = all(report[family]["state"] != "UNKNOWN" for family in ("ipv4", "ipv6"))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report))
    return int(not ok)


if __name__ == "__main__":
    raise SystemExit(main())
