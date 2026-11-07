"""Private durable journals and lifetime process exclusion on local POSIX storage."""

from contextlib import closing, contextmanager, nullcontext
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import struct

from ..errors import Denied


def directory_sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def protected_bytes(path, *, owner, maximum=16384, exact_mode=None, private=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) & 0o022
                or (private and stat.S_IMODE(info.st_mode) not in (0o400, 0o600))
                or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)
                or info.st_size > maximum):
            raise Denied("PROTECTED_FILE_INVALID")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise Denied("PROTECTED_FILE_INVALID")
        return data
    finally:
        os.close(fd)


def _credential_permissions(info, acl, owner, readonly):
    """Accept systemd's root-owned named-user ACL or its chown fallback."""
    if (not readonly or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size != 32 or owner <= 0):
        return False
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == owner and mode == 0o400:
        return True
    # Linux POSIX ACL xattr v2: root read, exactly this user read, no group or
    # other access. The group mode bits represent the ACL mask, not group access.
    expected = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in (
        (1, 4, 0xffffffff), (2, 4, owner), (4, 0, 0xffffffff),
        (16, 4, 0xffffffff), (32, 0, 0xffffffff)))
    return info.st_uid == 0 and mode == 0o440 and acl == expected


def systemd_credential_bytes(path, *, owner):
    """Read a 32-byte credential without treating a root-owned ACL as public."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        acl = None
        if info.st_uid == 0:
            try:
                acl = os.getxattr(fd, "system.posix_acl_access")
            except OSError:
                pass
        if not _credential_permissions(info, acl, owner, bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)):
            raise Denied("SYSTEMD_CREDENTIAL_INVALID")
        data = os.read(fd, 33)
        if len(data) != 32:
            raise Denied("SYSTEMD_CREDENTIAL_INVALID")
        return data
    finally:
        os.close(fd)


def new_private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory_sync(Path(path).parent)


@contextmanager
def process_lock(path, *, shared_gid=None):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o660 if shared_gid else 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o007:
            raise Denied("PROCESS_LOCK_INVALID")
        if shared_gid is not None and info.st_gid != shared_gid:
            raise Denied("PROCESS_LOCK_INVALID")
        if shared_gid is not None:
            os.fchmod(fd, 0o660)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Denied("PROCESS_ALREADY_RUNNING", 409) from None
        yield
    finally:
        os.close(fd)


class Journal:
    def __init__(self, path, *, version=1, writers=None):
        self.path = Path(path).absolute()
        self.version = version
        self.writers = writers

    @classmethod
    def initialize(cls, path, schema, *, version=1):
        journal = cls(path, version=version)
        journal.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent = journal.path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise Denied("JOURNAL_PERMISSIONS")
        new_private_file(journal.path, b"")
        with journal.connect(initializing=True) as db:
            db.executescript("BEGIN IMMEDIATE;\n" + schema + f"\nPRAGMA user_version={version};")
            db.execute("COMMIT")
        directory_sync(journal.path.parent)
        return journal

    @contextmanager
    def connect(self, *, initializing=False):
        info, parent = self.path.lstat(), self.path.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or info.st_uid != os.geteuid() or parent.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or stat.S_IMODE(parent.st_mode) != 0o700):
            raise Denied("JOURNAL_PERMISSIONS")
        if sqlite3.sqlite_version_info < (3, 45):
            raise Denied("SQLITE_VERSION_UNSUPPORTED")
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, autocommit=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            if initializing:
                db.execute("PRAGMA journal_mode=WAL")
            for name, expected in {"journal_mode": "wal", "synchronous": 2, "foreign_keys": 1,
                                   "busy_timeout": 5000, "user_version": 0 if initializing else self.version}.items():
                if db.execute(f"PRAGMA {name}").fetchone()[0] != expected:
                    raise Denied("JOURNAL_CONTRACT_MISMATCH")
            try:
                yield db
            finally:
                if db.in_transaction:
                    db.execute("ROLLBACK")

    @contextmanager
    def write(self, *, kind="control"):
        admission = self.writers.writer(kind) if self.writers else nullcontext()
        with admission:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
