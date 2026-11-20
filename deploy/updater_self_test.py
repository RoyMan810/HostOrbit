"""Run the verified updater's fixed self-test in a transient systemd sandbox."""

import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from deploy.artifact import file_at
from deploy.update_release import PLATFORM
from vpn_orbit.errors import Denied


EXECUTABLE = "vpn-orbit-updater"
MAX_EXECUTABLE = 64 * 1024 * 1024


def zstd_runtime():
    try:
        from compression import zstd
    except ImportError as error:
        raise Denied("UPDATER_ZSTD_UNAVAILABLE") from error
    return zstd


def unpack_updater(package, version, output):
    # The input is a signed private copy. Limit decompression before interpreting
    # the header and accept only a single USTAR file, without extended headers.
    zstd = zstd_runtime()

    archive = f"vpn-orbit-updater-{PLATFORM}-{version}.tar.zst"
    try:
        with file_at(package, archive) as (fd, _):
            with os.fdopen(fd, "rb", closefd=False) as stream, zstd.ZstdFile(
                stream, options={zstd.DecompressionParameter.window_log_max: 27},
            ) as payload:
                header = payload.read(tarfile.BLOCKSIZE)
                entry = tarfile.TarInfo.frombuf(header, "ascii", "strict")
                if (header[257:263] != b"ustar\0" or entry.name != EXECUTABLE
                        or entry.type != tarfile.REGTYPE or not 1 <= entry.size <= MAX_EXECUTABLE
                        or entry.linkname or not entry.mode & 0o111):
                    raise Denied("UPDATER_ARCHIVE_INVALID")
                remaining = entry.size
                with output.open("xb") as binary:
                    while remaining and (chunk := payload.read(min(remaining, 1024 * 1024))):
                        binary.write(chunk)
                        remaining -= len(chunk)
                padding = (-entry.size) % tarfile.BLOCKSIZE
                tail = payload.read(padding + tarfile.RECORDSIZE + 1)
                if remaining or not padding + 1024 <= len(tail) <= padding + tarfile.RECORDSIZE or any(tail):
                    raise Denied("UPDATER_ARCHIVE_INVALID")
    except (tarfile.HeaderError, zstd.ZstdError, UnicodeError, EOFError) as error:
        raise Denied("UPDATER_ARCHIVE_INVALID") from error
    output.chmod(0o555)


def run_updater_self_test(package, version):
    with tempfile.TemporaryDirectory(prefix=".updater-self-test-", dir=package.parent) as directory:
        root = Path(directory)
        unpack_updater(package, version, root / EXECUTABLE)
        # PID 1 resolves the root directory before dropping the service UID.
        root.chmod(0o755)
        command = [
            "/usr/bin/systemd-run", "--system", "--wait", "--collect", "--quiet", "--service-type=exec",
            f"--property=RootDirectory={root}", "--property=WorkingDirectory=/",
            "--property=DynamicUser=yes", "--property=CapabilityBoundingSet=",
            "--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes",
            "--property=PrivateDevices=yes", "--property=ProtectSystem=strict",
            "--property=ProtectProc=invisible", "--property=ProcSubset=pid",
            "--property=SystemCallArchitectures=native",
            "--property=SystemCallFilter=~@network-io @mount @privileged",
            "--property=SystemCallErrorNumber=EPERM",
            "--property=RestrictSUIDSGID=yes", "--property=TasksMax=16",
            "--property=MemoryMax=64M", "--property=RuntimeMaxSec=10s",
            "--property=TimeoutStartSec=10s", "--property=TimeoutStopSec=2s",
            "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=null",
            "--", f"/{EXECUTABLE}", "--self-test",
        ]
        try:
            subprocess.run(command, check=True, timeout=25, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env={"PATH": "/usr/bin:/bin"})
        except (OSError, subprocess.SubprocessError) as error:
            raise Denied("UPDATER_SELF_TEST_FAILED") from error
