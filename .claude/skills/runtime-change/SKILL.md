---
name: runtime-change
description: Apply HostOrbit's security and verification checklist when changing runtime, credentials, SSH, Docker, backup, or recovery code.
---

Before changing the requested behavior, inspect the relevant code, callers, tests, documentation and trust boundaries. Trace input validation, authorization and scope, credential handling, persistent state, failure and retry behavior, and any effects on remote hosts or recovery. Preserve existing safeguards and compatibility; do not expose secrets in logs or test output.

Add focused regression tests for changed behavior, including denial and failure paths where relevant. Follow CONTRIBUTING.md and the relevant CI workflows to select checks and identify required acceptance evidence. Do not modify historical evidence to manufacture a pass.

Native fixtures and `--isolated-vm` labs are only for disposable VMs. Never run them on the user's workstation. Obtain explicit permission before privileged operations, deployment, or changes to real hosts or credentials. Report checks passed, failed, and skipped.
