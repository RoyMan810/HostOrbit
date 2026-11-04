import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'lib/register.py'
spec = importlib.util.spec_from_file_location('monitor_register', SCRIPT)
reg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reg)
# A valid Ed25519 SSH public key fixture: only format/identity tested here.
PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXbXvPRoUBGdkA0SwsNK4jeCs6PM71VayZ/1ds4wM7r test-only'

class Registration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.config = d / 'config.json'
        self.auth = d / 'authorized_keys'
        self.config.write_text(json.dumps({'probes': []}))
        self.auth.write_text('')

    def register(self, **kwargs):
        return reg.register(self.config, self.auth,
                            kwargs.get('pid','ru1-to-nl1'), 'RU→NL',
                            kwargs.get('pub',PUB), kwargs.get('source','192.0.2.20'), 720, 2, 1)

    def test_new_and_retry_are_idempotent(self):
        self.register()
        self.register()
        self.assertEqual(len(json.loads(self.config.read_text())['probes']),1)
        self.assertEqual(len(self.auth.read_text().splitlines()),1)

    def test_interrupted_registration_recovers(self):
        self.register()
        self.config.write_text(json.dumps({'probes': []}))
        self.register()
        self.assertEqual(len(json.loads(self.config.read_text())['probes']),1)
        self.assertEqual(len(self.auth.read_text().splitlines()),1)

    def test_cannot_reuse_same_public_key_for_another_probe(self):
        self.register()
        with self.assertRaisesRegex(ValueError, 'already present'):
            self.register(pid='ru2-to-nl1')
        self.assertEqual(len(self.auth.read_text().splitlines()), 1)

    def test_wrong_source_rejected(self):
        self.register()
        with self.assertRaises(ValueError):
            self.register(source='192.0.2.21')
        self.assertEqual(len(self.auth.read_text().splitlines()),1)

if __name__ == '__main__': unittest.main()
