"""Textual's Bash side speaks a private prompt protocol; no root required."""
import ast
import base64
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "lib/textual_protocol.sh"
COMMON = ROOT / "lib/common.sh"
APP = ROOT / "lib/textual_ui.py"


class BridgeTests(unittest.TestCase):
    def call(self, script, answers):
        return subprocess.run(
            ["bash", "-c", script, "bash", str(COMMON)],
            input=answers, text=True, capture_output=True,
            env={**os.environ, "KVPN_TEXTUAL_IPC": "1", "KVPN_TUI": "0"},
            timeout=5,
        )

    def test_input_frame_does_not_pollute_captured_result(self):
        r = self.call('source "$1"; result=$(ask_default "Choose field" "443"); printf "value=%s" "$result"', '8443\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "value=8443")
        self.assertIn("__KVPN_UI_PROMPT__\tinput\t", r.stderr)
        self.assertIn(base64.b64encode(b"Choose field").decode(), r.stderr)

    def test_empty_input_keeps_original_default(self):
        r = self.call('source "$1"; result=$(ask_default "Port" "22"); printf "%s" "$result"', '\n')
        self.assertEqual(r.stdout, "22")

    def test_user_cancellation_is_fail_closed(self):
        r = self.call('source "$1"; ask_default "Danger" ""; echo MUST_NOT_RUN', '__KVPN_UI_CANCEL__\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("MUST_NOT_RUN", r.stdout)

    def test_confirmation_no_is_rejected(self):
        r = self.call('source "$1"; confirm "Open UFW?" && echo BAD || echo DECLINED', 'no\n')
        self.assertEqual(r.returncode, 0)
        self.assertIn('DECLINED', r.stdout)
        self.assertNotIn('BAD', r.stdout)

    def test_secret_not_echoed_or_logged(self):
        r = self.call('source "$1"; v=$(kvpn_ipc_request password "token" ""); [[ "$v" == private-test-secret ]]', 'private-test-secret\n')
        self.assertEqual(r.returncode, 0)
        self.assertNotIn('private-test-secret', r.stdout + r.stderr)

    def test_app_is_syntactically_valid_without_installed_textual(self):
        ast.parse(APP.read_text())

    def test_launchers_and_bash_syntax(self):
        scripts = [PROTOCOL, COMMON, ROOT / 'lib/textual_launcher.sh', ROOT / 'lib/tui.sh', ROOT / 'install.sh', ROOT / 'monitor-kit/install.sh']
        r = subprocess.run(['bash', '-n', *map(str, scripts)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_all_actions_are_allowlisted_no_shell_execution(self):
        source = APP.read_text()
        self.assertIn('asyncio.create_subprocess_exec(', source)
        self.assertNotIn('create_subprocess_shell', source)
        self.assertNotIn('shell=True', source)
        self.assertIn('password=self.kind == "password"', source)
        self.assertIn('KVPN_TEXTUAL_IPC', source)


if __name__ == "__main__":
    unittest.main()
