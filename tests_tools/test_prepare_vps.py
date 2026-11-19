import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_vps


class PrepareVpsTests(unittest.TestCase):
    def test_fingerprint_mismatch_stops_before_provisioning(self):
        with patch.object(prepare_vps.subprocess, "check_output", return_value="host ssh-ed25519 YWJj\n"):
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                prepare_vps.identify_host("192.0.2.20", 22, "SHA256:" + "A" * 43)

    def test_both_login_methods_use_the_pin_and_generate_a_separate_probe_key(self):
        blob = b"test host key"
        encoded = base64.b64encode(blob).decode()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        for use_key in (False, True):
            with self.subTest(use_key=use_key), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                admin_key = directory / "admin"
                admin_key.touch()
                output = directory / "target"
                argv = ["prepare_vps.py", "--host", "192.0.2.20", "--port", "2222",
                        "--user", "admin", "--fingerprint", fingerprint, "--output", str(output)]
                expected_auth = "PreferredAuthentications=keyboard-interactive,password"
                if use_key:
                    argv += ["--identity", str(admin_key)]
                    expected_auth = "PreferredAuthentications=publickey"

                def run(cmd, **kwargs):
                    if cmd[0] == "ssh-keygen":
                        Path(str(output / "probe") + ".pub").write_bytes(b"ssh-ed25519 test\n")
                    else:
                        self.assertIn("StrictHostKeyChecking=yes", cmd)
                        self.assertIn(expected_auth, cmd)
                        self.assertEqual(str(admin_key) in cmd, use_key)
                        line = next(arg for arg in cmd if arg.startswith("UserKnownHostsFile="))
                        self.assertEqual(Path(line.split("=", 1)[1]).read_text(),
                                         f"[192.0.2.20]:2222 ssh-ed25519 {encoded}\n")

                with (patch("sys.argv", argv), patch("builtins.print"),
                      patch.object(prepare_vps.subprocess, "run", side_effect=run) as runner,
                      patch.object(prepare_vps.subprocess, "check_output", side_effect=[
                          f"[192.0.2.20]:2222 ssh-ed25519 {encoded}\n", '{"v":8,"uid":0}']) as reader):
                    prepare_vps.main()
                self.assertEqual(runner.call_count, 2)
                probe = reader.call_args.args[0]
                self.assertIn(str(output / "probe"), probe)
                self.assertNotIn(str(admin_key), probe)
                policy = json.loads((output / "targets.json").read_text())["targets"][0]
                self.assertEqual(policy["capabilities"], ["host.probe"])
                self.assertEqual(policy["port"], 2222)

    def test_generated_profile_is_valid_shell(self):
        subprocess.run(["sh", "-n"], input=prepare_vps.provision(b"ssh-ed25519 test\n"),
                       text=True, check=True)
