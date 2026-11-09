import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / ".claude/hooks/file_checks.py"


def run_hook(event, path, root):
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"hook_event_name": event, "tool_input": {"file_path": str(path)}}),
        text=True, capture_output=True, env={**os.environ, "CLAUDE_PROJECT_DIR": str(root)},
    )


class FileHookTests(unittest.TestCase):
    def test_secret_edits_ask_but_examples_do_not(self):
        with tempfile.TemporaryDirectory() as root:
            for name in (".env", ".env.production", "server.key", "credentials.json"):
                result = run_hook("PreToolUse", Path(root) / name, root)
                self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")
            self.assertEqual(run_hook("PreToolUse", Path(root) / ".env.example", root).stdout, "")

    def test_python_edits_run_ruff_and_report_failure(self):
        with tempfile.TemporaryDirectory() as root:
            bin_dir = Path(root) / ".venv/bin"
            bin_dir.mkdir(parents=True)
            ruff = bin_dir / "ruff"
            ruff.write_text("#!/bin/sh\nprintf 'lint failure\\n'\nexit 1\n")
            ruff.chmod(0o755)
            result = run_hook("PostToolUse", Path(root) / "example file.py", root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("lint failure", result.stderr)
            self.assertEqual(run_hook("PostToolUse", Path(root) / "file.ts", root).returncode, 0)


if __name__ == "__main__":
    unittest.main()
