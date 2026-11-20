from compression import zstd
import io
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
from threading import Event, Thread
import unittest

from deploy.updater_self_test import EXECUTABLE, unpack_updater
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
        from nacl.signing import SigningKey

        from deploy.build_update_release import build_release
        from deploy.supervised_update import select_update, slot_name
        from hostorbit.database import identifier
        from hostorbit.runtime.authority import Authority
        from hostorbit.runtime.ipc import Client, handle
        from fixtures import policy, trusted_time

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
        clock = lambda: 1_800_000_000
        authority = Authority.initialize(self.root / "gate", policy(), clock=clock,
                                         time_health=trusted_time(self.root / "time", clock))
        self.addCleanup(authority.close)
        listener = self.enterContext(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        address = self.root / "supervisor.sock"
        listener.bind(str(address))
        listener.listen()
        listener.settimeout(0.2)
        stop = Event()

        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    handle(connection, authority.dispatch, {(0, 0): "updater"})

        server = Thread(target=serve, daemon=True)
        server.start()
        try:
            client = Client(address, server_uids={0})
            signer = SigningKey.generate()
            slots = self.root / "slots"
            images = {name: "sha256:" + "a" * 64 for name in ("web", "api", "worker")}
            for result, installed, candidate in ((0, "1.1.0", "1.2.0"), (17, "1.2.0", "1.3.0")):
                subprocess.run(["/usr/bin/cc", "-static", f"-DSELF_TEST_RESULT={result}", "-o", binary, source],
                               check=True, timeout=20)
                self.pack(binary.read_bytes())
                release = self.root / candidate
                compatibility = dict(installed=installed, bootstrap="1.0.0", minimum_release="1.0.0",
                                     schema=3, vault_format=1)
                signed = build_release(release, self.archive, signer, release_version=candidate,
                                       schema_to=3, images=images, **compatibility)
                approval = {"plan_id": identifier(), "revision": 1, "approval_id": identifier(),
                            "release_sha256": signed["release_sha256"]}
                if result:
                    with self.assertRaisesRegex(Denied, "UPDATER_SELF_TEST_FAILED"):
                        select_update(release, slots, bytes(signer.verify_key), client, approval, **compatibility)
                    self.assertTrue((slots / "pending.json").is_file())
                else:
                    selected = select_update(release, slots, bytes(signer.verify_key), client, approval, **compatibility)
                    self.assertEqual(selected["self_test"], "PASSED")
                self.assertEqual(slot_name(slots), "A")
                with authority.journal.connect() as db:
                    state = db.execute("SELECT state FROM gate").fetchone()[0]
                self.assertEqual(state, "MAINTENANCE" if result else "NORMAL")
        finally:
            stop.set()
            server.join(5)
