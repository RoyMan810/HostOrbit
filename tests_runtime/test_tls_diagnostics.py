from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from vpn_orbit.runtime.listener_diagnostics import main


class TlsDiagnosticsTests(unittest.TestCase):
    def test_checks_tls_identity_and_expiry_against_the_given_ip(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cert, key = directory / "server.pem", directory / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
             "-subj", "/CN=legacy.example", "-addext", "subjectAltName=DNS:site.example",
             "-out", cert, "-keyout", key], check=True, capture_output=True, timeout=10,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        names = []
        server_context.set_servername_callback(lambda _, name, __: names.append(name))

        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)

            def handshake(status):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(4)
                    try:
                        with server_context.wrap_socket(connection, server_side=True) as secured:
                            if status is not None:
                                with secured.makefile("rb") as request:
                                    self.assertEqual(request.readline(), b"HEAD /healthz HTTP/1.1\r\n")
                                    self.assertEqual(request.readline(), f"Host: site.example:{listener.getsockname()[1]}\r\n".encode())
                                    self.assertEqual(request.readline(), b"Connection: close\r\n")
                                    self.assertEqual(request.readline(), b"\r\n")
                                secured.sendall(f"HTTP/1.1 {status} Fixture\r\nLocation: https://other.example/\r\n\r\n".encode())
                            return True
                    except ssl.SSLError:
                        return False

            cases = (
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", None),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 204),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 302),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 503),
                ("legacy.example", {"SSL_CERT_FILE": str(cert)}, "CERTIFICATE_INVALID", 200),
                ("site.example", {}, "CERTIFICATE_INVALID", None),
            )
            for name, env, expected, status in cases:
                with self.subTest(name=name, state=expected, status=status):
                    future = executor.submit(handshake, status)
                    output = io.StringIO()
                    args = ["--connect", "127.0.0.1", "--port", str(listener.getsockname()[1]), "--tls-name", name]
                    if status is not None:
                        args.extend(["--https-path", "/healthz"])
                    with patch.dict(os.environ, env), redirect_stdout(output):
                        code = main(args)
                    report = json.loads(output.getvalue())
                    self.assertEqual(report["tcp_reachability"], "CONNECTED")
                    self.assertEqual(report["tls"]["state"], expected)
                    self.assertEqual(report["tls"]["server_name"], name)
                    self.assertEqual(future.result(timeout=5), expected == "VERIFIED")
                    self.assertEqual(code, int(expected != "VERIFIED" or status in (302, 503)))
                    if status is not None:
                        https = {"state": "RESPONDED", "status": status} if expected == "VERIFIED" else {"state": "NOT_TESTED"}
                        self.assertEqual(report["https"], https)
                    else:
                        self.assertNotIn("https", report)
                    if expected == "VERIFIED":
                        self.assertGreater(report["tls"]["expires_at"], time.time())
                    else:
                        self.assertNotIn("expires_at", report["tls"])
        self.assertEqual(names, ["site.example"] * 4 + ["legacy.example", "site.example"])

    def test_tls_mode_keeps_tcp_refusal_separate(self):
        with socket.socket() as listener, redirect_stdout(io.StringIO()) as out:
            listener.bind(("127.0.0.1", 0))
            code = main(["--connect", "127.0.0.1", "--port", str(listener.getsockname()[1]),
                         "--tls-name", "site.example"])
        self.assertEqual(code, 1)
        report = json.loads(out.getvalue())
        self.assertEqual(report["tcp_reachability"], "REFUSED")
        self.assertEqual(report["tls"], {"state": "NOT_TESTED", "server_name": "site.example"})

    def test_invalid_tls_arguments_are_rejected_before_network_io(self):
        for args in (["--tls-name", "site.example"],
                     ["--connect", "127.0.0.1", "--tls-name", "https://site.example"],
                     ["--connect", "127.0.0.1", "--tls-name", "127.0.0.1"],
                     ["--connect", "127.0.0.1", "--https-path", "/healthz"],
                     ["--connect", "127.0.0.1", "--tls-name", "site.example", "--https-path", "//other.example/"],
                     ["--connect", "127.0.0.1", "--tls-name", "site.example", "--https-path", "/path\r\nHost: fake"]):
            with self.subTest(args=args), patch.object(socket, "socket") as transport:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    main(["--port", "443", *args])
                self.assertEqual(exc.exception.code, 2)
                transport.assert_not_called()
