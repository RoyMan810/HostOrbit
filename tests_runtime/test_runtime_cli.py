import subprocess
import sys
import unittest
from contextlib import nullcontext
from unittest.mock import patch

from hostorbit.runtime.cli import run


class RuntimeCliTests(unittest.TestCase):
    def test_cli_import_does_not_load_broker_or_ssh(self):
        subprocess.run([sys.executable, "-c", "import sys; import hostorbit.runtime.cli; "
                        "assert 'hostorbit.runtime.broker' not in sys.modules; assert 'asyncssh' not in sys.modules"],
                       check=True, timeout=15)

    def test_broker_commands_load_broker_when_needed(self):
        config = {"app_uid": 1, "app_gid": 2, "worker_uid": 3, "worker_gid": 4, "broker_uid": 5,
                  "broker_gid": 6, "targets": "/targets", "vault_credential": "/credential",
                  "vault_directory": "/vault", "broker_directory": "/broker", "gate_socket": "/gate",
                  "broker_socket": "/socket", "public_verify_key": "/public"}
        with (patch("hostorbit.runtime.cli.os.geteuid", return_value=5),
              patch("hostorbit.runtime.cli.Policy.load") as policy,
              patch("hostorbit.runtime.cli.Vault") as vault,
              patch("hostorbit.runtime.broker.Broker") as broker,
              patch("hostorbit.runtime.cli.protected_bytes", return_value=b"key"),
              patch("hostorbit.runtime.cli.process_lock", return_value=nullcontext()),
              patch("hostorbit.runtime.cli.serve") as serve):
            run(config, "initialize-broker")
            vault.initialize.assert_called_once()
            broker.initialize.assert_called_once_with("/broker", policy.return_value)
            run(config, "broker", listener=object())
            broker.return_value.recover.assert_called_once()
            serve.assert_called_once()


if __name__ == "__main__":
    unittest.main()
