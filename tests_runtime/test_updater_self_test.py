from compression import zstd
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from deploy.updater_self_test import EXECUTABLE, run_updater_self_test, unpack_updater
from hostorbit.errors import Denied


VERSION = "1.2.0"


class UpdaterSelfTestTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.package = self.root / "package"
        self.package.mkdir()
        self.archive = self.package / f"hostorbit-updater-linux-amd64-{VERSION}.tar.zst"

    def pack(self, data, *, name=EXECUTABLE, mode=0o755, extra=False):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            executable = tarfile.TarInfo(name)
            executable.mode = mode
            executable.size = len(data)
            archive.addfile(executable, io.BytesIO(data))
            if extra:
                archive.addfile(tarfile.TarInfo("extra"))
        self.archive.write_bytes(zstd.compress(buffer.getvalue()))

    def test_unpack_only_the_single_executable(self):
        self.pack(b"test-binary")
        output = self.root / "binary"
        unpack_updater(self.package, VERSION, output)
        self.assertEqual(output.read_bytes(), b"test-binary")
        self.assertEqual(output.stat().st_mode & 0o777, 0o555)

    def test_rejects_invalid_layout_and_trailing_files(self):
        for index, options in enumerate(({"name": "../outside"}, {"mode": 0o644}, {"extra": True})):
            self.pack(b"test-binary", **options)
            with self.subTest(options=options), self.assertRaisesRegex(Denied, "UPDATER_ARCHIVE_INVALID"):
                unpack_updater(self.package, VERSION, self.root / f"invalid-{index}")
        self.assertFalse((self.root / "outside").exists())

    @unittest.skipUnless(os.environ.get("HOSTORBIT_NATIVE_UPDATER_TEST") == "1", "requires dedicated Ubuntu systemd runner")
    def test_real_systemd_sandbox_drops_root_and_blocks_host_files_and_sockets(self):
        self.assertEqual(os.geteuid(), 0)
        source = self.root / "test.c"
        source.write_text("""
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--self-test")) return 1;
    if (!geteuid() || !getegid()) return 2;
    if (open("/etc/passwd", O_RDONLY) >= 0 ||
        open("/proc/1/root/etc/passwd", O_RDONLY) >= 0) return 3;
    if (socket(AF_INET, SOCK_STREAM, 0) >= 0 ||
        socket(AF_UNIX, SOCK_STREAM, 0) >= 0) return 4;
    return SELF_TEST_RESULT;
}
""", encoding="utf-8")
        binary = self.root / "test"
        for result in (0, 17):
            subprocess.run(["/usr/bin/cc", "-static", f"-DSELF_TEST_RESULT={result}", "-o", binary, source],
                           check=True, timeout=20)
            self.pack(binary.read_bytes())
            if result:
                with self.assertRaisesRegex(Denied, "UPDATER_SELF_TEST_FAILED"):
                    run_updater_self_test(self.package, VERSION)
            else:
                run_updater_self_test(self.package, VERSION)
