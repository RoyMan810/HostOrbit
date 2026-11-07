"""Host-bound OS wrapping; no plaintext credential file, argv or environment."""

import os
from pathlib import Path
import stat
import subprocess

from ..errors import Denied
from .storage import new_private_file


def seal_credential(key, destination):
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    if not isinstance(key, bytes) or len(key) != 32:
        raise Denied("VAULT_KEY_INVALID")
    destination = Path(destination).absolute()
    for parent in destination.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Denied("CREDENTIAL_PARENT_UNTRUSTED")
    parent = destination.parent.lstat()
    if stat.S_IMODE(parent.st_mode) != 0o700:
        raise Denied("CREDENTIAL_DIRECTORY_NOT_PRIVATE")
    if destination.exists() or destination.is_symlink():
        raise Denied("CREDENTIAL_ALREADY_EXISTS")
    try:
        result = subprocess.run(["/usr/bin/systemd-creds", "encrypt", "--with-key=host", "--name=broker-dek", "-", "-"],
            input=key, capture_output=True, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("OS_CREDENTIAL_SEAL_FAILED") from None
    if result.returncode or not 64 <= len(result.stdout) <= 16384:
        raise Denied("OS_CREDENTIAL_SEAL_FAILED")
    new_private_file(destination, result.stdout)


def initialize_credential(config):
    # Losing or changing an existing working DEK must never look like fresh init.
    directory = Path(config["vault_directory"])
    if not directory.is_dir() or any(directory.iterdir()):
        raise Denied("EXISTING_VAULT_MUST_NOT_REKEY")
    seal_credential(os.urandom(32), config["vault_credential"])
