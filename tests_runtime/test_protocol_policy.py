import copy
import json
import unittest

from hostorbit.errors import Denied
from hostorbit.runtime.policy import Target
from hostorbit.runtime.protocol import canonical, decode
from fixtures import TARGET, policy


class ProtocolPolicyTests(unittest.TestCase):
    def test_noncanonical_duplicates_nonfinite_deep_or_large_frames_are_rejected(self):
        for value in (b'{"a":1,"a":2}', b'{"a": 1}', b'{"a":NaN}', b'[' * 20 + b'0' + b']' * 20, b'x' * 16385):
            with self.subTest(value=value[:40]), self.assertRaises(Denied):
                decode(value)
        self.assertEqual(decode(canonical({"v": 1, "operation": "probe"})), {"v": 1, "operation": "probe"})
        self.assertEqual(decode(b' {"a":1}\n', canonical_required=False), {"a": 1})

    def test_fixed_numeric_targets_reject_loopback_metadata_zones_dns_and_unsupported_actions(self):
        original = policy().targets[TARGET].value
        for address in ("127.0.0.1", "169.254.169.254", "fe80::1%eth0", "2130706433", "0177.0.0.1", "unregistered.example", "100.100.100.200"):
            value = {**original, "ip": address}
            with self.subTest(address=address), self.assertRaises(Denied):
                Target.parse(value)
        for change in ({"capabilities": ["shell"]}, {"capabilities": ["host.probe"], "command": "sh"}, {"secret_ref": "../../key"}):
            with self.subTest(change=change), self.assertRaises(Denied):
                Target.parse({**original, **change})
