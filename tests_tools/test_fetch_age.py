from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
import urllib.request

from tools import fetch_age


class AgeDownloadTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.directory / 'age.tar.gz'
        self.payload = b'fixture-archive'
        self.replies = [(200, self.payload), (200, self.payload)]
        self.requests = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                i = int(self.path.strip('/'))
                fixture.requests.append(i)
                code, body = fixture.replies[i]
                self.send_response(code)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_port}'
        self.enterContext(patch.object(fetch_age, 'SOURCES', (base + '/0', base + '/1')))
        self.enterContext(patch.object(fetch_age, 'SHA256', hashlib.sha256(self.payload).hexdigest()))

    def test_downloaded_bytes_are_verified_before_publication(self):
        fetch_age.fetch(self.output)
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assertEqual(self.requests, [0])

    def test_http_504_uses_second_official_route(self):
        self.replies[0] = (504, b'gateway timeout')
        fetch_age.fetch(self.output)
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assertEqual(self.requests, [0, 1])

    def test_corrupt_bytes_fail_closed_without_trying_another_archive(self):
        self.replies[0] = (200, b'corrupted-archive')
        with self.assertRaisesRegex(ValueError, 'CHECKSUM'):
            fetch_age.fetch(self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.requests, [0])

    def test_failed_routes_leave_no_partial_archive(self):
        self.replies[:] = [(504, b'gateway timeout'), (504, b'gateway timeout')]
        with self.assertRaisesRegex(RuntimeError, 'UNAVAILABLE'):
            fetch_age.fetch(self.output)
        self.assertFalse(self.output.exists())

    def test_oversized_response_and_existing_destination_are_rejected(self):
        with patch.object(fetch_age, 'MAX_BYTES', 4), self.assertRaisesRegex(ValueError, 'SIZE'):
            fetch_age.fetch(self.output)
        self.assertFalse(self.output.exists())
        self.output.write_bytes(b'existing archive')
        with self.assertRaises(FileExistsError):
            fetch_age.fetch(self.output)
        self.assertEqual(self.output.read_bytes(), b'existing archive')

    def test_https_redirect_cannot_downgrade_to_http(self):
        with self.assertRaisesRegex(ValueError, 'HTTPS'):
            fetch_age.HTTPSRedirect().redirect_request(urllib.request.Request('https://example.org'),
                                                       None, 302, 'redirect', {}, 'http://example.org/archive')
