---
name: pr-check
description: Run the checks relevant to the current HostOrbit changes and report their results before a PR.
disable-model-invocation: true
---

Inspect the working tree, including staged and untracked changes, without changing or discarding them. Read CONTRIBUTING.md and the relevant CI workflows; select checks based on the actual changes and run those feasible in the current environment.

- From the repository root, the documented checks include `.venv/bin/ruff check .`, `.venv/bin/python tools/check_repository.py`, and the unittest discovery suites `tests_tools`, `tests`, `tests_app`, and `tests_runtime`.
- For web changes, follow web/README.md and .github/workflows/web-ui.yml for the build and Playwright tests. Respect the pinned runtime and browser requirements.
- Do not install dependencies, change credentials, create a PR, or run privileged or destructive labs without explicit permission. Native fixtures and `--isolated-vm` labs are only for disposable VMs, never the user's workstation.
- Report each command and its result, failed and skipped checks with reasons, and relevant CI-only labs and evidence/acceptance implications. Do not claim a check passed if it did not run.
