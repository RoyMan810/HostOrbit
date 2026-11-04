"""Regression tests for the distributed self-extracting single-file CLI."""
import base64
import io
from pathlib import Path
import subprocess
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / 'kvpn-install.sh'


class Distribution(unittest.TestCase):
    def test_standalone_matches_runtime_sources(self):
        check = subprocess.run(['python3', str(ROOT / 'tools/build_bundle.py'), '--check'],
                               capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn('up to date', check.stdout)
        body = WRAPPER.read_text()
        self.assertEqual(body.count('__KVPN_INSTALL_PAYLOAD_BELOW__\n'), 1)
        payload = body.split('__KVPN_INSTALL_PAYLOAD_BELOW__\n', 1)[1]
        with tarfile.open(fileobj=io.BytesIO(__import__('gzip').decompress(base64.b64decode(payload))), mode='r:') as t:
            names = t.getnames()
            self.assertIn('kvpn-node-deployer/install.sh', names)
            self.assertNotIn('kvpn-node-deployer/kvpn-install.sh', names,
                             'Standalone installer must not recursively embed another installer')
            self.assertFalse(any('/docs/' in name or '/tests/' in name for name in names))
            for member in t.getmembers():
                self.assertTrue(member.isfile(), member.name)
                self.assertFalse(member.name.startswith('/'))
                source = ROOT / member.name.removeprefix('kvpn-node-deployer/')
                self.assertEqual(t.extractfile(member).read(), source.read_bytes(), member.name)

    def test_standalone_command_available(self):
        result = subprocess.run(['bash', str(WRAPPER), 'help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('monitor public-keys', result.stdout)

    def test_installation_is_fail_closed_and_diagnostic(self):
        script = (ROOT / 'install.sh').read_text()
        self.assertLess(script.index('docker compose pull'), script.index('setup_firewall "$panel_ip"', script.index('validate_compose "$staging"')))
        self.assertIn('do not repeat full wizard', script)
        monitor = (ROOT / 'monitor-kit/install.sh').read_text()
        self.assertIn('for attempt in 1 2 3', monitor)
        self.assertIn('[[ "$actual" == "$expected" ]]', monitor)
        self.assertIn('monitor_status()', monitor)
        self.assertIn('public-keys) show_public_keys', monitor)

if __name__ == '__main__':
    unittest.main()
