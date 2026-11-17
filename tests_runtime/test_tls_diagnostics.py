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

from hostorbit.runtime.listener_diagnostics import main


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

            def handshake():
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(4)
                    try:
                        with server_context.wrap_socket(connection, server_side=True):
                            return True
                    except ssl.SSLError:
                        return False

            cases = (
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED"),
                ("legacy.example", {"SSL_CERT_FILE": str(cert)}, "CERTIFICATE_INVALID"),
                ("site.example", {}, "CERTIFICATE_INVALID"),
            )
            for name, env, expected in cases:
                with self.subTest(name=name, state=expected):
                    future = executor.submit(handshake)
                    output = io.StringIO()
                    with patch.dict(os.environ, env), redirect_stdout(output):
                        code = main(["--connect", "127.0.0.1", "--port", str(listener.getsockname()[1]),
                                     "--tls-name", name])
                    report = json.loads(output.getvalue())
                    self.assertEqual(report["tcp_reachability"], "CONNECTED")
                    self.assertEqual(report["tls"]["state"], expected)
                    self.assertEqual(report["tls"]["server_name"], name)
                    self.assertEqual(future.result(timeout=5), expected == "VERIFIED")
                    self.assertEqual(code, int(expected != "VERIFIED"))
                    if expected == "VERIFIED":
                        self.assertGreater(report["tls"]["expires_at"], time.time())
                    else:
                        self.assertNotIn("expires_at", report["tls"])
        self.assertEqual(names, ["site.example", "legacy.example", "site.example"])

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
                     ["--connect", "127.0.0.1", "--tls-name", "127.0.0.1"]):
            with self.subTest(args=args), patch.object(socket, "socket") as transport:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    main(["--port", "443", *args])
                self.assertEqual(exc.exception.code, 2)
                transport.assert_not_called()
