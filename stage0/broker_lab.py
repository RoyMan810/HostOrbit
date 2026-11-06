"""Linux AF_UNIX peer-credential lab for AC-B10."""

import argparse
import os
from pathlib import Path
import socket
import struct


PROBE = b'{"operation":"probe"}\n'
_CREDENTIALS = struct.Struct("=iII")  # Linux struct ucred: pid_t, uid_t, gid_t.
_MAX_FRAME = 256


def probe_response(connection: socket.socket, worker: tuple[int, int]) -> bytes:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
    _, uid, gid = _CREDENTIALS.unpack(raw)
    with connection.makefile("rb") as reader:
        frame = reader.read(_MAX_FRAME + 1)
    if (uid, gid) != worker:
        return b"PEER_DENIED\n"
    if frame != PROBE:
        return b"INVALID_REQUEST\n"
    return b"OK\n"


def serve(path: Path, worker: tuple[int, int]) -> None:
    # Set the intended socket permissions at bind time, before a peer can connect.
    os.umask(0o117)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(3)
                try:
                    connection.sendall(probe_response(connection, worker))
                except OSError:
                    continue


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket", type=Path)
    parser.add_argument("worker_uid", type=int)
    parser.add_argument("worker_gid", type=int)
    args = parser.parse_args()
    worker = (args.worker_uid, args.worker_gid)
    if any(not 0 < identity < 2**31 for identity in worker):
        parser.error("Worker UID and GID must be non-root numeric identities")
    serve(args.socket, worker)


if __name__ == "__main__":
    main()
