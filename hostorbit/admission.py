"""Host-owned writer admission shared by SQLite writers in separate processes.

The lock inode is permanent. The state is replaced atomically in its root-owned
directory, which containers mount read-only. Always acquire before BEGIN, and
never hold it while waiting for a remote effect or another service's RPC.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import time

from .errors import Denied


_PHASES = {"OPEN", "CLOSING_ADMISSION", "SHORT_BARRIER", "RECOVERY_HOLD"}
_KINDS = {"business", "dispatch", "control"}
_ID = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


class Admission:
    def __init__(self, directory, *, owner=0, timeout=35):
        self.directory = Path(directory).absolute()
        self.owner, self.timeout = owner, timeout
        if not 0 < timeout <= 35:
            raise ValueError("WRITER_TIMEOUT_INVALID")

    def _directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o755:
            os.close(fd)
            raise Denied("WRITER_STATE_INVALID", 503)
        return fd

    def _file(self, parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size > 512):
            os.close(fd)
            raise Denied("WRITER_STATE_INVALID", 503)
        return fd

    @staticmethod
    def _validate(value):
        if (not isinstance(value, dict) or set(value) != {"v", "phase", "snapshot_id"}
                or type(value["v"]) is not int or value["v"] != 1 or value["phase"] not in _PHASES
                or (value["snapshot_id"] is not None and (not isinstance(value["snapshot_id"], str)
                                                         or _ID.fullmatch(value["snapshot_id"]) is None))
                or (value["phase"] == "OPEN" and value["snapshot_id"] is not None)
                or (value["phase"] in {"CLOSING_ADMISSION", "SHORT_BARRIER"} and value["snapshot_id"] is None)):
            raise Denied("WRITER_STATE_INVALID", 503)
        return value

    def _state(self, parent):
        fd = self._file(parent, "state.json")
        try:
            raw = os.read(fd, 513)
            value = json.loads(raw)
            if raw != json.dumps(value, sort_keys=True, separators=(",", ":")).encode():
                raise ValueError("noncanonical state")
            return self._validate(value)
        except (ValueError, TypeError, UnicodeError):
            raise Denied("WRITER_STATE_INVALID", 503) from None
        finally:
            os.close(fd)

    def state(self):
        try:
            parent = self._directory()
            try:
                return self._state(parent)
            finally:
                os.close(parent)
        except OSError:
            raise Denied("WRITER_STATE_UNAVAILABLE", 503) from None

    @classmethod
    def initialize(cls, directory, *, owner=0):
        if os.geteuid() != owner:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        admission = cls(directory, owner=owner)
        admission.directory.mkdir(mode=0o755)
        admission.directory.chmod(0o755)
        parent = admission._directory()
        try:
            fd = os.open("writers.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
            try:
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        finally:
            os.close(parent)
        # A half-finished initialization cannot admit writers.
        admission.publish("RECOVERY_HOLD")
        return admission

    def publish(self, phase, snapshot_id=None):
        if os.geteuid() != self.owner:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        value = self._validate({"v": 1, "phase": phase, "snapshot_id": snapshot_id})
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        parent = self._directory()
        name = ".state-" + os.urandom(16).hex()
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
            try:
                os.fchmod(fd, 0o644)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(name, "state.json", src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        except BaseException:
            # A failed closing publication must not leave an old OPEN latch.
            # Missing state is fail-closed for every writer. Recovery reconstructs
            # it only after the independent control journal is writable again.
            try:
                os.unlink("state.json", dir_fd=parent)
                os.fsync(parent)
            except FileNotFoundError:
                pass
            raise
        finally:
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    @contextmanager
    def writer(self, kind="business"):
        if kind not in _KINDS:
            raise ValueError("WRITER_KIND_INVALID")
        parent = fd = None
        until = time.monotonic() + self.timeout
        try:
            parent = self._directory()
            fd = self._file(parent, "writers.lock")
            while True:
                held = False
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    held = True
                    state = self._state(parent)
                    if state["phase"] != "SHORT_BARRIER":
                        if kind != "control" and state["phase"] != "OPEN":
                            raise Denied("WRITER_ADMISSION_CLOSED", 503, retry_after=1)
                        break
                except BlockingIOError:
                    pass
                if held:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                if time.monotonic() >= until:
                    raise Denied("WRITER_BARRIER_TIMEOUT", 503, retry_after=1)
                time.sleep(min(0.01, max(0, until - time.monotonic())))
        except OSError:
            raise Denied("WRITER_STATE_UNAVAILABLE", 503) from None
        else:
            yield
        finally:
            if fd is not None:
                os.close(fd)  # Closing releases a held flock, including after rollback.
            if parent is not None:
                os.close(parent)

    @contextmanager
    def exclusive(self, *, timeout):
        if os.geteuid() != self.owner or not 0 < timeout <= 30:
            raise Denied("WRITER_COORDINATOR_IDENTITY_INVALID")
        parent, fd = self._directory(), None
        try:
            fd = self._file(parent, "writers.lock")
            until = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= until:
                        raise Denied("SNAPSHOT_BARRIER_TIMEOUT", 503)
                    time.sleep(min(0.01, max(0, until - time.monotonic())))
            yield
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def verify_barrier(self, snapshot_id):
        """A Broker capture helper must see both the root latch and exclusion.

        This does not grant eligibility: the independent Coordinator must still
        bind the local result to its own completed capture and provenance.
        """
        parent, fd = self._directory(), None
        try:
            fd = self._file(parent, "writers.lock")
            state = self._state(parent)
            if state["phase"] != "SHORT_BARRIER" or state["snapshot_id"] != snapshot_id:
                raise Denied("SNAPSHOT_BINDING_INVALID", 503)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            raise Denied("SNAPSHOT_EXCLUSION_REQUIRED", 503)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)
