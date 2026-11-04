from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PublicSafety(unittest.TestCase):
    def test_no_hardcoded_live_addresses_or_private_tokens(self):
        for path in ROOT.rglob('*'):
            if not path.is_file() or path.suffix not in ('.sh','.md','.txt','.py','.json','.yml'):
                continue
            value=path.read_text(errors='replace')
            for addr in re.findall(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])',value):
                self.assertIn(addr, ('127.0.0.1', '0.0.0.0'), str(path))
            self.assertIsNone(re.search(r'\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b',value),str(path))
            self.assertNotIn('-----BEGIN '+ 'OPENSSH PRIVATE KEY-----',value)

if __name__=='__main__': unittest.main()
