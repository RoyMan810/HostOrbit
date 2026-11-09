#!/usr/bin/env python3
"""Claude Code hooks to protect secret files and run Ruff after edits."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    data = json.load(sys.stdin)
    path = Path(data.get("tool_input", {}).get("file_path", ""))
    event = data.get("hook_event_name")
    name = path.name.lower()
    if event == "PreToolUse":
        sensitive = (
            (name == ".env" or name.startswith(".env.")) and not name.endswith((".example", ".sample", ".template"))
            or name in {"credentials.json", "secrets.json", "id_rsa", "id_ed25519"}
            or name.endswith((".pem", ".key", ".p12", ".pfx"))
        )
        if sensitive:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "This file may contain secrets or private keys."}}))
    elif event == "PostToolUse" and path.suffix == ".py":
        root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
        local_ruff = root / ".venv/bin/ruff"
        ruff = str(local_ruff) if local_ruff.is_file() else shutil.which("ruff")
        if not ruff:
            print("Ruff check skipped: install the project's quality dependencies in .venv.", file=sys.stderr)
            return 1
        result = subprocess.run([ruff, "check", "--", str(path)], cwd=root, capture_output=True, text=True)
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
