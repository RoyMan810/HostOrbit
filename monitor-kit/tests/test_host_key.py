"""Security regression tests for monitor SSH host key verification."""
import base64
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from verify_host_key import HostKeyError, fingerprint_for_key, verify_scan


def key_row(byte, host='203.0.113.5'):
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([byte]) * 32
    encoded = base64.b64encode(wire).decode()
    return f'{host} ssh-ed25519 {encoded}', f"SHA256:{base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')}"


class HostKeyVerificationTest(unittest.TestCase):
    def test_one_key(self):
        row, fp = key_row(1)
        self.assertEqual(verify_scan(row + '\n', fp), 1)
        self.assertEqual(fingerprint_for_key(row.split()[2]), fp)

    def test_same_key_multiple_addresses(self):
        row, fp = key_row(1)
        row2, _ = key_row(1, '[panel.example]:2222')
        self.assertEqual(verify_scan(row + '\n' + row2 + '\n', fp), 2)

    def test_reject_different_key_in_second_record(self):
        row, fp = key_row(1)
        attacker, _ = key_row(2)
        with self.assertRaisesRegex(HostKeyError, 'mismatch'):
            verify_scan(row + '\n' + attacker, fp)

    def test_reject_invalid_rows_and_empty_scan(self):
        row, fp = key_row(1)
        for contents in ['', '# banner\n', row + '\nnot-a-key', row.replace('ssh-ed25519', 'ssh-rsa')]:
            with self.subTest(contents=contents):
                with self.assertRaises(HostKeyError):
                    verify_scan(contents, fp)

    def test_reject_corrupted_blob(self):
        row, fp = key_row(1)
        for contents in [row + 'junk', row.replace('AAAA', 'AABA', 1)]:
            with self.subTest(contents=contents):
                with self.assertRaises(HostKeyError):
                    verify_scan(contents, fp)

    def test_reject_invalid_expected(self):
        row, fp = key_row(1)
        with self.assertRaises(HostKeyError):
            verify_scan(row, fp + '=')


if __name__ == '__main__':
    unittest.main()
