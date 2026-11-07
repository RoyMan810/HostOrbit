"""One fixed SSH operation with in-process keys, pinned host identity and bounded streams."""

import asyncio
import os
import time

import asyncssh

from ..errors import Denied
from .protocol import decode, fields, integer, text
from .storage import new_private_file, protected_bytes


PROBE_REQUEST = b'{"operation":"probe","version":1}\n'
PROBE_COMMAND = "hostorbit.v1.probe"


def validate_private_key(key):
    try:
        imported = asyncssh.import_private_key(key)
        if imported.get_algorithm() != "ssh-ed25519":
            raise ValueError
        return imported
    except (asyncssh.KeyImportError, ValueError, TypeError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED") from None


async def bounded_read(stream):
    result = bytearray()
    while True:
        chunk = await stream.read(1024)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > 2048:
            raise Denied("SSH_UNSUPPORTED_OUTPUT")


async def exchange(target, key, known_hosts):
    connection = await asyncssh.connect(
        target.value["ip"], port=target.value["port"], username="hostorbit-svc",
        client_keys=[key], agent_path=None, config=None,
        known_hosts=str(known_hosts), host_key_alias=f"ho-{target.id}",
        preferred_auth=["publickey"], password_auth=False, kbdint_auth=False,
        gss_auth=False, agent_forwarding=False, connect_timeout=4, login_timeout=5,
    )
    try:
        process = await connection.create_process(PROBE_COMMAND, input=PROBE_REQUEST, encoding=None, request_pty=False)
        output, _, _ = await asyncio.gather(bounded_read(process.stdout), bounded_read(process.stderr), process.wait_closed())
        if process.exit_status != 0:
            raise Denied("SSH_REMOTE_PROBE_FAILED")
        return output
    finally:
        connection.close()
        try:
            await asyncio.wait_for(connection.wait_closed(), 1)
        except asyncio.TimeoutError:
            connection.abort()


def probe(target, private_key, known_hosts):
    key = validate_private_key(private_key)
    async def bounded():
        return await asyncio.wait_for(exchange(target, key, known_hosts), 12)
    try:
        output = asyncio.run(bounded())
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("SSH_HOST_KEY_MISMATCH") from None
    except asyncssh.PermissionDenied:
        raise Denied("SSH_AUTHENTICATION_FAILED") from None
    except asyncssh.KeyExchangeFailed:
        raise Denied("SSH_KEY_EXCHANGE_FAILED") from None
    except asyncssh.ConnectionLost:
        raise Denied("SSH_CONNECTION_LOST") from None
    except asyncssh.ProtocolError:
        raise Denied("SSH_PROTOCOL_ERROR") from None
    except (asyncio.TimeoutError, TimeoutError):
        raise Denied("SSH_TIMEOUT") from None
    except OSError:
        raise Denied("SSH_NETWORK_UNAVAILABLE") from None
    except asyncssh.Error:
        raise Denied("SSH_CONNECTION_FAILED") from None
    # Arbitrary third-party stdout/stderr is never a public result, log payload or exception message.
    try:
        value = decode(output.rstrip(b"\n"))
    except Denied:
        raise Denied("SSH_UNSUPPORTED_OUTPUT") from None
    fields(value, ("v", "uid", "boot_id", "observed_at"))
    if type(value["v"]) is not int or value["v"] != 1 or type(value["uid"]) is not int or value["uid"] != 0:
        raise Denied("SSH_PROBE_INVALID")
    text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    integer(value["observed_at"], int(time.time()) - 300, int(time.time()) + 2)
    return {"status": "REACHABLE", "source": "restricted_helper", "observed_at": value["observed_at"], "boot_id": value["boot_id"]}


def provision_known_hosts(path, policy):
    new_private_file(path, "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode())


def verify_known_hosts(path, policy):
    expected = "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode()
    if protected_bytes(path, owner=os.geteuid(), exact_mode=0o600) != expected:
        raise Denied("SSH_PINNED_KEYS_INVALID")
