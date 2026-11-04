"""Non-mutating tests for the interactive multi-mode installer."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = str(ROOT / 'install.sh')
COMMON = str(ROOT / 'lib/common.sh')


def bash(code):
    return subprocess.run(['bash', '-c', code, 'bash', INSTALL], text=True, capture_output=True)


class MenuAndCompatibility(unittest.TestCase):
    def test_os_allowlist_ubuntu_24_26(self):
        valid = ['24.04', '26.04', '26.10']
        rejected = ['22.04', '24.10', '25.04', '25.10', '27.04']
        for version in valid:
            with self.subTest(version=version):
                self.assertEqual(bash(f'source "$1"; supported_distribution ubuntu {version}').returncode, 0)
        for version in rejected:
            with self.subTest(version=version):
                self.assertNotEqual(bash(f'source "$1"; supported_distribution ubuntu {version}').returncode, 0)

    def test_validate_ipv4_and_ports_without_python(self):
        p = subprocess.run(['bash', '-c', '''
source "$1"
python3() { exit 92; }
valid_ipv4 127.0.0.1 && valid_ipv4 192.0.2.1 &&
! valid_ipv4 256.0.0.1 && ! valid_ipv4 01.2.3.4 &&
valid_ip_or_cidr 127.0.0.1/32 && ! valid_ip_or_cidr 127.0.0.1/33 &&
valid_port 1 && valid_port 65535 && ! valid_port 65536 && ! valid_port 999999999999
''', 'bash', COMMON], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_ufw_is_independent_of_node_docker(self):
        p = bash('''
source "$1"
require_debian(){ :; }
preflight(){ :; }
confirm(){ return 0; }
ask_default(){
 case "$1" in
   'Role '*) echo foreign;;
   'Remnawave Panel '*) echo 127.0.0.1;;
   'Node API '*) echo 2222;;
   'Xray TCP '*) echo 8443;;
   'Allowed RU '*) echo 127.0.0.1;;
   'Current SSH '*) echo 22;;
   'Allow public '*) echo no;;
   *) exit 4;;
 esac
}
setup_firewall(){ printf 'FIREWALL_ONLY %s\\n' "$*"; }
install_node(){ echo 'BAD: install_node called'; return 2; }
install_docker(){ echo 'BAD: install_docker called'; return 2; }
configure_firewall_only
''')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('FIREWALL_ONLY 127.0.0.1 2222 8443 127.0.0.1 22 no', p.stdout)
        self.assertNotIn('BAD:', p.stdout)

    def test_node_only_requires_restricted_ufw(self):
        cases = [
            ('enabled', '2222/tcp ALLOW 127.0.0.1', True),
            ('enabled', '2222/tcp ALLOW IN 127.0.0.1', True),
            ('enabled', '2222/tcp ALLOW IN Anywhere', False),
            ('enabled', 'Anywhere ALLOW IN Anywhere', False),
            ('enabled', '2222/tcp ALLOW Anywhere', False),
            ('enabled', '2222/tcp ALLOW 198.51.100.2', False),
            ('disabled', '2222/tcp ALLOW 127.0.0.1', False),
        ]
        for active, rule, accepted in cases:
            with self.subTest(active=active, rule=rule):
                code = '''
source "$1"
ufw(){
  if [[ "$*" == 'status verbose' ]]; then
    printf '%s\\n' 'Status: ACTIVE' 'Default: deny (incoming), allow (outgoing)'
  else
    printf '%s\\n' 'Status: active' '__RULE__'
  fi
}
__OVERRIDE__
assert_node_api_protected 127.0.0.1 2222
'''.replace('__RULE__', rule).replace('__OVERRIDE__', 'ufw(){ printf "Status: inactive\\n"; }' if active=='disabled' else '')
                p=bash(code)
                self.assertEqual(p.returncode == 0, accepted, p.stdout+'\n'+p.stderr)

    def test_no_editor_required(self):
        text=(ROOT / 'install.sh').read_text()
        self.assertNotIn('tar gzip nano', text)
        self.assertIn('nano is optional', text)
        self.assertIn('install_node node_only', text)
        self.assertIn('configure_firewall_only', text)
        self.assertIn('menu|tui) menu', text)

if __name__ == '__main__':
    unittest.main()
