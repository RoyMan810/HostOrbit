"""Non-destructive checks for keyboard terminal menus and structured inputs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / 'lib/tui.sh'
INSTALL = ROOT / 'install.sh'
MONITOR = ROOT / 'monitor-kit/install.sh'

class TerminalUI(unittest.TestCase):
    def run_with_fake_ui(self, func, exitcode=0):
        with tempfile.TemporaryDirectory() as d:
            mock = Path(d, 'whiptail')
            mock.write_text('#!/bin/sh\nprintf "ans" >&2\nexit ' + str(exitcode) + '\n')
            mock.chmod(0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ['PATH'], KVPN_TUI='1')
            cmd = 'source "$1"; kvpn_ui_ready(){ return 0; }; ' + func
            return subprocess.run(['bash', '-c', cmd, 'bash', str(UI)], env=env, capture_output=True, text=True)

    def test_input_captures_dialog_result(self):
        result=self.run_with_fake_ui('[[ "$(kvpn_ui_input hello default)" == ans ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_password_not_printed(self):
        result=self.run_with_fake_ui('v=$(kvpn_ui_password token); [[ "$v" == ans ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('ans', result.stdout)

    def test_cancel_is_not_silent_success(self):
        result=self.run_with_fake_ui('kvpn_ui_input question default >/dev/null', 1)
        self.assertNotEqual(result.returncode, 0)

    def test_confirmation_respects_dialog_exit(self):
        ok=self.run_with_fake_ui('kvpn_ui_confirm continue')
        cancel=self.run_with_fake_ui('kvpn_ui_confirm continue',1)
        self.assertEqual(ok.returncode,0)
        self.assertEqual(cancel.returncode,1)

    def test_ssh_terminal_80x24_uses_dynamic_dimensions(self):
        script='''
source "$1"
stty(){ echo "24 80"; }
kvpn_ui_geometry
[[ "$KVPN_UI_W" == 78 && "$KVPN_UI_H" == 22 ]]
'''
        result=subprocess.run(['script','-q','-e','-c', 'bash -c '+__import__('shlex').quote(script.replace('\"$1\"', __import__('shlex').quote(str(UI))).replace('\"$1\"', __import__('shlex').quote(str(UI)))), '/dev/null'], capture_output=True,text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_migration_commands_in_distributed_cli(self):
        self.assertNotIn('legacy-audit', INSTALL.read_text())
        self.assertNotIn('legacy-audit', MONITOR.read_text())
        self.assertFalse((ROOT/'docs/MONITOR-MIGRATION.md').exists())
        self.assertFalse((ROOT/'monitor-kit/tests/test_migration.py').exists())

    def test_main_menu_is_fullscreen_and_has_sections(self):
        text=UI.read_text()
        for name in ('--menu', '--inputbox', '--passwordbox', '--radiolist', '--yesno', '--textbox'):
            self.assertIn(name, text)
        self.assertIn('kvpn_ui_monitor_menu', text)
        self.assertIn('kvpn_ui_firewall_menu', text)
        self.assertIn('KVPN_TUI=1', text)

if __name__ == '__main__': unittest.main()
