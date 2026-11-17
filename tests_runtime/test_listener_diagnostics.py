import errno
import io
import json
from pathlib import Path
import socket
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from hostorbit.runtime.listener_diagnostics import _read_bindings, inspect_port, main


_HEADER = b"  sl  local_address rem_address   st tx_queue\n"


def _row(address, port, state=b"0A"):
    packed = socket.inet_pton(socket.AF_INET6 if ":" in address else socket.AF_INET, address)
    words = [packed[i:i + 4] for i in range(0, len(packed), 4)]
    rendered = b"".join(f"{int.from_bytes(word, sys.byteorder):08X}".encode() for word in words)
    return b"  0: " + rendered + f":{port:04X}".encode() + b" 00000000:0000 " + state + b" 0:0\n"


class ListenerDiagnosticsTests(unittest.TestCase):
    def test_parses_only_the_selected_listening_port_and_deduplicates_addresses(self):
        table = _HEADER + b"".join((
            _row("127.0.0.1", 8443), _row("127.0.0.1", 8443), _row("0.0.0.0", 8444), _row("192.0.2.1", 8443, b"01"),
        ))
        self.assertEqual(_read_bindings(io.BytesIO(table), 8443, 4), ["127.0.0.1"])
        self.assertEqual(_read_bindings(io.BytesIO(table), 8445, 4), [])

    def test_parses_ipv6_wildcard_and_multiword_address(self):
        table = _HEADER + _row("::", 8443) + _row("2001:db8:1234:5678:90ab:cdef:1234:5678", 8443)
        self.assertEqual(_read_bindings(io.BytesIO(table), 8443, 6), ["::", "2001:db8:1234:5678:90ab:cdef:1234:5678"])

    def test_marks_invalid_and_unavailable_tables_as_unknown(self):
        with patch.object(Path, "open", side_effect=[io.BytesIO(_HEADER + b"broken row\n"), PermissionError()]):
            result = inspect_port(8443)
        for family in ("ipv4", "ipv6"):
            self.assertEqual(result[family], {"state": "UNKNOWN", "addresses": []})
        self.assertEqual(result["external_reachability"], "NOT_TESTED")

    def test_rejects_out_of_range_ports(self):
        for port in (0, 65536, True, "443"):
            with self.subTest(port=port), self.assertRaisesRegex(ValueError, "port must be"):
                inspect_port(port)

    def test_cli_ignores_bound_socket_until_it_listens(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
            self.assertEqual(inspect_port(port)["ipv4"], {"state": "NOT_LISTENING", "addresses": []})
            server.listen()
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--port", str(port)])
            report = json.loads(output.getvalue())
            self.assertEqual(code, int(report["ipv6"]["state"] == "UNKNOWN"))
            self.assertEqual(report["scope"], "CURRENT_NETWORK_NAMESPACE")
            self.assertEqual(report["ipv4"], {"state": "LISTENING", "addresses": ["127.0.0.1"]})
            self.assertEqual(report["external_reachability"], "NOT_TESTED")

    def test_real_ipv6_loopback_listener(self):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError as error:
            self.skipTest(f"IPv6 sockets unavailable: {error}")
        with server:
            try:
                server.bind(("::1", 0))
            except OSError as error:
                self.skipTest(f"IPv6 loopback unavailable: {error}")
            server.listen()
            report = inspect_port(server.getsockname()[1])
            self.assertEqual(report["ipv6"], {"state": "LISTENING", "addresses": ["::1"]})
            self.assertEqual(report["external_reachability"], "NOT_TESTED")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--port", str(report["port"]), "--connect", "::1"]), 0)
            self.assertEqual(json.loads(output.getvalue())["tcp_reachability"], "CONNECTED")


    def test_connect_mode_distinguishes_refusal_and_a_successful_tcp_handshake(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
            args = ["--port", str(port), "--connect", "127.0.0.1"]
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 1)
            self.assertEqual(json.loads(output.getvalue())["tcp_reachability"], "REFUSED")
            server.listen()
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report, {"address": "127.0.0.1", "port": port, "protocol": "tcp",
                                      "scope": "FROM_PROBE_HOST", "tcp_reachability": "CONNECTED"})
            server.settimeout(1)
            conn, _ = server.accept()
            with conn:
                self.assertEqual(conn.recv(1), b"")

    def test_connect_mode_classifies_errors_without_exposing_diagnostics(self):
        for error, state in ((TimeoutError("private diagnostic"), "TIMED_OUT"),
                             (OSError(errno.ENETUNREACH, "private diagnostic"), "UNREACHABLE"),
                             (PermissionError("private diagnostic"), "ERROR")):
            with self.subTest(state=state), patch("hostorbit.runtime.listener_diagnostics.socket.socket") as transport:
                conn = transport.return_value.__enter__.return_value
                conn.connect.side_effect = error
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(["--port", "443", "--connect", "2001:db8::1"]), 1)
                self.assertEqual(json.loads(output.getvalue())["tcp_reachability"], state)
                self.assertNotIn("private diagnostic", output.getvalue())
                transport.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
                conn.settimeout.assert_called_once_with(3)
                conn.connect.assert_called_once_with(("2001:db8::1", 443))

    def test_connect_mode_rejects_invalid_destinations_before_opening_a_socket(self):
        for address in ("example.org", "::", "224.0.0.1", "fe80::1%eth0", "fe80::1", "255.255.255.255"):
            with self.subTest(address=address), patch.object(socket, "socket") as transport:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(["--port", "443", "--connect", address])
                self.assertEqual(error.exception.code, 2)
                transport.assert_not_called()
