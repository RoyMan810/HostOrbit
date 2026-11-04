"""Safety-oriented tests for manual legacy migration and Telegram test mode."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
MONITOR = ROOT / 'monitor-kit/lib/monitor.py'

spec = importlib.util.spec_from_file_location('monitor_migration', MONITOR)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Migration(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'legacy audit needs root to inspect /root')
    def test_legacy_audit_read_only(self):
        result = subprocess.run(['bash', str(ROOT / 'monitor-kit/install.sh'), 'legacy-audit'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('read-only', result.stdout)
        self.assertIn('No known legacy', result.stdout)

    def test_installer_does_not_remove_legacy(self):
        code = (ROOT / 'monitor-kit/install.sh').read_text()
        self.assertIn('existing panel monitor detected', code)
        self.assertIn('legacy probe SSH key still registered', code)
        self.assertNotIn('rm -rf /root/kvpn-monitor', code)

    def test_test_telegram_does_not_modify_states(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            token = base / 'token'; token.write_text('fake-test-token')
            config = base / 'config.json'
            config.write_text(json.dumps({'chat_id': '-1001234', 'thread_id': 42, 'token_file': str(token), 'state_dir': str(base / 'state'), 'probes': []}))
            with patch.object(sys, 'argv', ['monitor.py', '--config', str(config), '--test-telegram']):
                with patch.object(m, 'send_telegram') as send:
                    with patch('builtins.print'):
                        m.main()
                send.assert_called_once()
            self.assertFalse((base / 'state').exists())

if __name__ == '__main__': unittest.main()
