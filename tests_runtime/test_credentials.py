from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hostorbit.errors import Denied
from hostorbit.runtime.credentials import initialize_credential, seal_credential


class CredentialTests(unittest.TestCase):
    def test_unprivileged_caller_cannot_invoke_the_host_sealing_helper(self):
        with patch("hostorbit.runtime.credentials.os.geteuid", return_value=1001), patch("hostorbit.runtime.credentials.subprocess.run") as command:
            with self.assertRaisesRegex(Denied, "LOCAL_ROOT_REQUIRED"):
                seal_credential(b"x" * 32, Path("/not-created/credential"))
            command.assert_not_called()

    def test_invalid_key_never_enters_a_subprocess(self):
        with patch("hostorbit.runtime.credentials.os.geteuid", return_value=0), patch("hostorbit.runtime.credentials.subprocess.run") as command:
            for key in (b"", b"x" * 31, b"x" * 33, "not bytes"):
                with self.subTest(length=len(key)), self.assertRaisesRegex(Denied, "VAULT_KEY_INVALID"):
                    seal_credential(key, Path("/not-created/credential"))
            command.assert_not_called()

    def test_missing_or_nonempty_vault_is_not_a_fresh_credential_initialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            config = {"vault_directory": str(vault), "vault_credential": str(root / "must-not-exist")}
            with patch("hostorbit.runtime.credentials.seal_credential") as seal:
                with self.assertRaisesRegex(Denied, "EXISTING_VAULT_MUST_NOT_REKEY"):
                    initialize_credential(config)
                vault.mkdir()
                (vault / "orphaned-ciphertext").write_bytes(b"existing data")
                with self.assertRaisesRegex(Denied, "EXISTING_VAULT_MUST_NOT_REKEY"):
                    initialize_credential(config)
                seal.assert_not_called()
                self.assertFalse(Path(config["vault_credential"]).exists())
