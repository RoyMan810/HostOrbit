import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from unittest.mock import patch

from vpn_orbit.runtime.cli import main, run
from fixtures import policy


class RuntimeCliTests(unittest.TestCase):
    def test_cli_import_does_not_load_broker_or_ssh(self):
        subprocess.run([sys.executable, "-c", "import sys; import vpn_orbit.runtime.cli; "
                        "assert 'vpn_orbit.runtime.broker' not in sys.modules; assert 'asyncssh' not in sys.modules"],
                       check=True, timeout=15)

    def test_installed_enrollment_catalog_requires_root_and_returns_only_the_projection(self):
        cfg = Path(__file__).resolve().parents[1] / "deploy/runtime.example.json"
        approved = policy()
        args = ["--config", str(cfg), "enrollment-catalog"]
        with (patch("vpn_orbit.runtime.cli.protected_bytes", return_value=cfg.read_bytes()),
              patch("vpn_orbit.runtime.cli.Policy.load", return_value=approved) as load,
              patch("vpn_orbit.runtime.cli.os.geteuid", return_value=0),
              redirect_stdout(io.StringIO()) as output):
            self.assertEqual(main(args), 0)
            load.assert_called_once_with(json.loads(cfg.read_bytes())["targets"], owner=0)
            self.assertEqual(json.loads(output.getvalue()), approved.enrollment_catalog())
            with patch("vpn_orbit.runtime.cli.os.geteuid", return_value=1), redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
            self.assertEqual(load.call_count, 1)
            output.truncate(0)
            output.seek(0)
            self.assertEqual(main([*args, "--ssh-endpoints"]), 0)
            self.assertEqual(json.loads(output.getvalue()), approved.enrollment_catalog(ssh_endpoints=True))

    def test_broker_commands_load_broker_when_needed(self):
        config = {"app_uid": 1, "app_gid": 2, "worker_uid": 3, "worker_gid": 4, "broker_uid": 5,
                  "broker_gid": 6, "targets": "/targets", "vault_credential": "/credential",
                  "vault_directory": "/vault", "broker_directory": "/broker", "gate_socket": "/gate",
                  "broker_socket": "/socket", "public_verify_key": "/public"}
        with (patch("vpn_orbit.runtime.cli.os.geteuid", return_value=5),
              patch("vpn_orbit.runtime.cli.Policy.load") as policy,
              patch("vpn_orbit.runtime.cli.Vault") as vault,
              patch("vpn_orbit.runtime.broker.Broker") as broker,
              patch("vpn_orbit.runtime.cli.protected_bytes", return_value=b"key"),
              patch("vpn_orbit.runtime.cli.process_lock", return_value=nullcontext()),
              patch("vpn_orbit.runtime.cli.serve") as serve):
            run(config, "initialize-broker")
            vault.initialize.assert_called_once()
            broker.initialize.assert_called_once_with("/broker", policy.return_value)
            run(config, "broker", listener=object())
            broker.return_value.recover.assert_called_once()
            serve.assert_called_once()


if __name__ == "__main__":
    unittest.main()
