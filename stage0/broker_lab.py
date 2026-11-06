"""Linux AF_UNIX peer-credential and scoped grant lab for AC-A04 and AC-B10."""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import time


PROBE = b'{"operation":"probe"}\n'
_CREDENTIALS = struct.Struct("=iII")  # Linux struct ucred: pid_t, uid_t, gid_t.
_MAX_FRAME = 1024
_USE_FIELDS = {
    "operation", "operation_id", "plan_digest", "resource", "secret_ref",
    "scope_digest", "permit", "nonce", "expires_at",
}


def fixture_use(frame: bytes, grant: Path, receipt: Path) -> bytes:
    try:
        request = json.loads(frame)
    except (ValueError, RecursionError):
        return b"INVALID_REQUEST\n"
    if (not isinstance(request, dict) or request.keys() != _USE_FIELDS
            or request["operation"] != "use_for_scoped_ssh"):
        return b"INVALID_REQUEST\n"
    if not grant.is_file() or not hmac.compare_digest(frame, grant.read_bytes()):
        return b"SCOPE_DENIED\n"
    expires_at = request["expires_at"]
    if type(expires_at) is not int or not 0 < expires_at - int(time.time()) <= 60:
        return b"PERMIT_EXPIRED\n"
    try:
        with receipt.open("xb") as output:
            output.write(hashlib.sha256(frame).digest())
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        return b"PERMIT_REPLAY\n"
    directory = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return b"USE_GRANTED\n"


def probe_response(connection: socket.socket, worker: tuple[int, int], grant: Path | None = None) -> bytes:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
    _, uid, gid = _CREDENTIALS.unpack(raw)
    with connection.makefile("rb") as reader:
        frame = reader.read(_MAX_FRAME + 1)
    if (uid, gid) != worker:
        return b"PEER_DENIED\n"
    if frame == PROBE:
        return b"OK\n"
    if grant is not None:
        receipt = Path(connection.getsockname()).with_name("permit-used")
        return fixture_use(frame, grant, receipt)
    return b"INVALID_REQUEST\n"


def serve(path: Path, worker: tuple[int, int], grant: Path | None = None) -> None:
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
                    connection.sendall(probe_response(connection, worker, grant))
                except OSError:
                    continue


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket", type=Path)
    parser.add_argument("worker_uid", type=int)
    parser.add_argument("worker_gid", type=int)
    parser.add_argument("--fixture-grant", type=Path)
    args = parser.parse_args()
    worker = (args.worker_uid, args.worker_gid)
    if any(not 0 < identity < 2**31 for identity in worker):
        parser.error("Worker UID and GID must be non-root numeric identities")
    serve(args.socket, worker, args.fixture_grant)


if __name__ == "__main__":
    main()
