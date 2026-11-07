import errno
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


with patch.object(sys, "path", [str(Path(__file__).with_name("lab")), *sys.path]):
    from ssh_systemd_docker import empty_cgroup


class CgroupObservationTests(unittest.TestCase):
    def test_offline_control_file_requires_a_later_empty_observation(self):
        group = Path("/sys/fs/cgroup/system.slice/fixture.service")
        with patch.object(Path, "read_text", side_effect=[
            OSError(errno.ENODEV, "No such device"), "populated 1\n", "populated 0\n",
        ]):
            self.assertFalse(empty_cgroup(group))
            self.assertFalse(empty_cgroup(group))
            self.assertTrue(empty_cgroup(group))

    def test_removed_cgroup_is_empty(self):
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assertTrue(empty_cgroup(Path("/removed/fixture")))

    def test_unrelated_read_errors_remain_failures(self):
        for code in (errno.EACCES, errno.EIO):
            with self.subTest(errno=code), patch.object(
                Path, "read_text", side_effect=OSError(code, "Cannot read cgroup"),
            ), self.assertRaises(OSError):
                empty_cgroup(Path("/unreadable/fixture"))
