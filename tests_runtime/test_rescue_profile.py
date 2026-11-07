from pathlib import Path
import unittest
from unittest.mock import patch

from hostorbit.errors import Denied
from hostorbit.runtime.rescue import offline_profile
from hostorbit.runtime.rescue_cli import console


class RescueProfileTests(unittest.TestCase):
    def profile(self, **changes):
        data = {"/etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n', "/proc/swaps": "Filename Type Size Used Priority\n",
                "/sys/power/state": "freeze mem\n", "/proc/net/dev": "header\nheader\nlo: 0 0\n",
                "/proc/meminfo": "MemAvailable: 8388608 kB\n"}
        data.update(changes)
        with patch("hostorbit.runtime.rescue.harden"), patch("os.geteuid", return_value=0), \
                patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
                patch.object(Path, "exists", return_value=False), patch.object(Path, "read_text", lambda p: data[str(p)]):
            return offline_profile()

    def test_exact_supported_profile(self):
        self.assertEqual(self.profile()["profile"], "ubuntu-24.04-amd64-offline-v1")

    def test_swap_hibernation_network_memory_and_platform_refuse(self):
        for path, value, code in (("/proc/swaps", "header\n/dev/zram0 partition 1 0 -2\n", "RESCUE_SWAP_ENABLED"),
                                  ("/sys/power/state", "freeze mem disk\n", "RESCUE_HIBERNATION_ENABLED"),
                                  ("/proc/net/dev", "header\nheader\nlo: 0\neth0: 1\n", "RESCUE_NETWORK_NOT_ISOLATED"),
                                  ("/proc/meminfo", "MemAvailable: 1 kB\n", "RESCUE_MEMORY_INSUFFICIENT"),
                                  ("/etc/os-release", "ID=debian\nVERSION_ID=13\n", "RESCUE_PLATFORM_UNSUPPORTED")):
            with self.subTest(path=path), self.assertRaisesRegex(Denied, code):
                self.profile(**{path: value})

    def test_noninteractive_digest_or_secret_input_refused(self):
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaisesRegex(Denied, "RESCUE_TRUSTED_CONSOLE_REQUIRED"):
                console()


if __name__ == "__main__":
    unittest.main()
