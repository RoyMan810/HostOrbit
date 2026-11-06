import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from stage0.broker_lab import PROBE, fixture_use, probe_response


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


class BrokerGrantTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.grant = root / "grant.json"
        self.receipt = root / "permit-used"
        self.body = {
            "operation": "use_for_scoped_ssh", "operation_id": "fixture-id", "plan_digest": "a" * 64,
            "resource": "managed", "secret_ref": "fixture-ssh", "scope_digest": "b" * 64,
            "permit": "c" * 64, "nonce": "d" * 32, "expires_at": 1060,
        }

    @staticmethod
    def frame(body):
        return json.dumps(body).encode("ascii") + b"\n"

    @patch("stage0.broker_lab.time.time", return_value=1000)
    def test_scope_mismatch_keeps_grant_unused_and_replay_is_rejected(self, _):
        allowed = self.frame(self.body)
        self.grant.write_bytes(allowed)
        foreign = self.frame({**self.body, "resource": "foreign"})
        self.assertEqual(fixture_use(foreign, self.grant, self.receipt), b"SCOPE_DENIED\n")
        self.assertFalse(self.receipt.exists())
        self.assertEqual(fixture_use(allowed, self.grant, self.receipt), b"USE_GRANTED\n")
        self.assertEqual(fixture_use(allowed, self.grant, self.receipt), b"PERMIT_REPLAY\n")

    @patch("stage0.broker_lab.time.time", return_value=1000)
    def test_expiry_is_enforced_without_consuming_the_grant(self, _):
        for expires_at in (1000, 999, 1061, True):
            with self.subTest(expires_at=expires_at):
                frame = self.frame({**self.body, "expires_at": expires_at})
                self.grant.write_bytes(frame)
                self.assertEqual(fixture_use(frame, self.grant, self.receipt), b"PERMIT_EXPIRED\n")
                self.assertFalse(self.receipt.exists())
