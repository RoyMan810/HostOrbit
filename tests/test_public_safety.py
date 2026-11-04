from pathlib import Path
import re
import ipaddress
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PublicSafety(unittest.TestCase):
    def test_no_hardcoded_live_addresses_or_private_tokens(self):
        for path in ROOT.rglob('*'):
            if not path.is_file() or path.suffix not in ('.sh','.md','.txt','.py','.json','.yml'):
                continue
            if 'tests' in path.relative_to(ROOT).parts:
                continue  # synthetic IPs, including deliberately malformed examples
            value=path.read_text(errors='replace')
            for addr in re.findall(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])',value):
                ip=ipaddress.ip_address(addr)
                reserved_doc_net=any(ip in ipaddress.ip_network(block) for block in (
                    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
                self.assertTrue(ip.is_loopback or ip.is_unspecified or reserved_doc_net, str(path)+': '+addr)
            self.assertIsNone(re.search(r'\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b',value),str(path))
            self.assertNotIn('-----BEGIN '+ 'OPENSSH PRIVATE KEY-----',value)

if __name__=='__main__': unittest.main()
