from contextlib import redirect_stderr, redirect_stdout
import io
import json
import socket
import unittest
from unittest.mock import patch

from hostorbit.runtime.listener_diagnostics import main


def _address_info(family, address):
    endpoint = (address, 0) if family == socket.AF_INET else (address, 0, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", endpoint


class DnsDiagnosticsTests(unittest.TestCase):
    def run_lookup(self, *options):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--resolve", "Site.Example.", *options])
        return code, json.loads(output.getvalue())

    @patch.object(socket, "getaddrinfo")
    def test_compares_the_complete_address_set_and_uses_an_absolute_name(self, lookup):
        lookup.return_value = [
            _address_info(socket.AF_INET6, "2001:0db8::1"),
            _address_info(socket.AF_INET, "192.0.2.10"),
            _address_info(socket.AF_INET, "192.0.2.10"),
        ]
        code, report = self.run_lookup("--expect-ip", "192.0.2.10", "--expect-ip", "2001:db8::1")
        self.assertEqual(code, 0)
        self.assertEqual(report["state"], "MATCH")
        self.assertEqual(report["scope"], "SYSTEM_RESOLVER")
        self.assertEqual(report["addresses"], ["192.0.2.10", "2001:db8::1"])
        lookup.assert_called_once_with("site.example.", None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        code, report = self.run_lookup("--expect-ip", "192.0.2.20")
        self.assertEqual(code, 1)
        self.assertEqual(report["state"], "MISMATCH")
        self.assertEqual(report["missing_addresses"], ["192.0.2.20"])
        self.assertEqual(report["unexpected_addresses"], ["192.0.2.10", "2001:db8::1"])

    @patch.object(socket, "getaddrinfo")
    def test_keeps_no_addresses_distinct_from_a_lookup_error(self, lookup):
        for error, state in ((socket.gaierror(socket.EAI_NONAME, "private detail"), "NO_ADDRESSES"),
                             (socket.gaierror(socket.EAI_AGAIN, "private detail"), "LOOKUP_FAILED")):
            with self.subTest(state=state):
                lookup.side_effect = error
                code, report = self.run_lookup()
                self.assertEqual(code, 1)
                self.assertEqual(report["state"], state)
                self.assertEqual(report["addresses"], [])
                self.assertNotIn("private detail", json.dumps(report))

    @patch.object(socket, "getaddrinfo")
    def test_lists_addresses_without_expectations(self, lookup):
        lookup.return_value = [_address_info(socket.AF_INET, "192.0.2.10")]
        code, report = self.run_lookup()
        self.assertEqual(code, 0)
        self.assertEqual(report["state"], "RESOLVED")
        self.assertNotIn("missing_addresses", report)

    @patch.object(socket, "getaddrinfo")
    def test_rejects_invalid_arguments_before_resolving(self, lookup):
        for args in (["--resolve", "https://site.example"],
                     ["--resolve", "site.example", "--expect-ip", "site.example"],
                     ["--resolve", "site.example", "--expect-ip", "fe80::1%eth0"],
                     ["--resolve", "site.example", "--port", "443"],
                     ["--port", "443", "--expect-ip", "192.0.2.1"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(args)
            self.assertEqual(exc.exception.code, 2)
        lookup.assert_not_called()
