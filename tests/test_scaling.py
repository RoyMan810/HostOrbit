# Multi-RU and multi-foreign safety tests: no real firewall changes
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]

def shell(code):
    return subprocess.run(['bash','-c', code,'bash',str(ROOT/'install.sh')],capture_output=True,text=True)

class Scaling(unittest.TestCase):
    def test_source_lists_validation(self):
        r=shell('''source "$1"
valid_ipv4_sources 192.0.2.11,198.51.100.22/32 &&
! valid_ipv4_sources 192.0.2.11,,198.51.100.22 &&
! valid_ipv4_sources 192.0.2.11, &&
! valid_ipv4_sources 999.1.2.3 &&
! valid_ipv4_sources 192.0.2.11/33 &&
! valid_ipv4_sources '192.0.2.11, 198.51.100.22'
''')
        self.assertEqual(r.returncode,0,r.stderr)

    def test_multiple_ufw_source_rules(self):
        r=shell('''source "$1"
install_packages(){ :; }
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
ufw(){
 if [[ "$*" == status* ]]; then echo 'Status: active'; echo 'Default: deny (incoming)'; return; fi
 printf 'UFW:%s\n' "$*" >> "$LOG"
}
confirm(){ return 0; }
setup_firewall 127.0.0.1 2222 8443 192.0.2.11,198.51.100.22 22 no
cat "$LOG"
''')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('from 192.0.2.11 to any port 8443',r.stdout)
        self.assertIn('from 198.51.100.22 to any port 8443',r.stdout)

    def test_multi_probe_systemd_units_and_key_isolation(self):
        text=(ROOT/'monitor-kit/install.sh').read_text()
        self.assertIn('kvpn-monitor-kit-probe@.service',text)
        self.assertIn('kvpn-monitor-kit-probe@.timer',text)
        self.assertIn('/etc/kvpn-monitor/probes/$pid.key',text)
        self.assertIn('refusing overwrite',text)
        self.assertIn('Repeat monitor ru / monitor foreign',text)

    def test_no_dangerous_existing_node_firewall_reset(self):
        text=(ROOT/'install.sh').read_text()
        self.assertIn('Existing node detected. Separate UFW setup is only for a NEW VPS',text)
        self.assertIn('Add ONLY this UFW rule?',text)

if __name__ == '__main__': unittest.main()
