import os
import socket
import unittest

from stage0.broker_lab import PROBE, probe_response


class BrokerProbeTests(unittest.TestCase):
    def response(self, frame, worker):
        peer, server = socket.socketpair()
        with peer, server:
            server.settimeout(2)
            peer.sendall(frame)
            peer.shutdown(socket.SHUT_WR)
            return probe_response(server, worker)

    def test_valid_peer_can_probe(self):
        self.assertEqual(self.response(PROBE, (os.geteuid(), os.getegid())), b"OK\n")

    def test_other_uid_or_gid_is_denied_even_with_a_forged_role(self):
        spoof = b'{"operation":"probe","consumer_kind":"worker"}\n'
        for expected in ((os.geteuid() + 1, os.getegid()), (os.geteuid(), os.getegid() + 1)):
            with self.subTest(expected=expected):
                self.assertEqual(self.response(spoof, expected), b"PEER_DENIED\n")

    def test_allowed_peer_still_has_a_fixed_request_schema(self):
        allowed = (os.geteuid(), os.getegid())
        for frame in (
            b'{"operation":"exec"}\n',
            b'{"operation":"probe","consumer_kind":"worker"}\n',
            PROBE + PROBE,
            b"x" * 512,
        ):
            with self.subTest(frame=frame[:40]):
                self.assertEqual(self.response(frame, allowed), b"INVALID_REQUEST\n")
