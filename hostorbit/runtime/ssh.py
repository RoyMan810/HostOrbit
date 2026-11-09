"""One fixed SSH operation with in-process keys, pinned host identity and bounded streams."""

import asyncio
import errno
import os
import time

import asyncssh

from ..errors import Denied
from .protocol import decode, docker_summary, fields, integer, software_summary, text
from .storage import new_private_file, protected_bytes


PROBES = (
    (3, "hostorbit.v3.probe", b'{"operation":"probe","version":3}\n'),
    (2, "hostorbit.v2.probe", b'{"operation":"probe","version":2}\n'),
    (1, "hostorbit.v1.probe", b'{"operation":"probe","version":1}\n'),
)


def validate_private_key(key):
    try:
        imported = asyncssh.import_private_key(key)
        if imported.get_algorithm() != "ssh-ed25519":
            raise ValueError
        return imported
    except (asyncssh.KeyImportError, ValueError, TypeError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED") from None


async def bounded_read(stream, limit=2048):
    result = bytearray()
    while True:
        chunk = await stream.read(1024)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > limit:
            raise Denied("SSH_UNSUPPORTED_OUTPUT")


async def exchange(target, key, known_hosts):
    connection = await asyncssh.connect(
        target.value["ip"], port=target.value["port"], username="hostorbit-svc",
        client_keys=[key], agent_path=None, config=None,
        known_hosts=str(known_hosts), host_key_alias=f"ho-{target.id}",
        x509_trusted_certs=None, x509_trusted_cert_paths=[],
        preferred_auth=["publickey"], password_auth=False, kbdint_auth=False,
        gss_auth=False, gss_kex=False, host_based_auth=False, server_host_key_algs=["ssh-ed25519"],
        agent_forwarding=False, connect_timeout=4, login_timeout=5,
    )
    try:
        for version, command, request in PROBES:
            process = await connection.create_process(command, input=request, encoding=None, request_pty=False)
            output, error, _ = await asyncio.gather(
                bounded_read(process.stdout, 4096 if version == 3 else 2048),
                bounded_read(process.stderr), process.wait_closed())
            if process.exit_status == 0:
                return version, output
            # The old forced command silently rejects an unsupported command with 65.
            if version == 1 or process.exit_status != 65 or output or error:
                break
        raise Denied("SSH_REMOTE_PROBE_FAILED")
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
        version, output = asyncio.run(bounded())
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
    except OSError as error:
        code = {errno.EACCES: "SSH_LOCAL_ACCESS_DENIED", errno.ENOENT: "SSH_LOCAL_FILE_MISSING",
                errno.ECONNREFUSED: "SSH_CONNECTION_REFUSED", errno.ENETUNREACH: "SSH_NETWORK_UNREACHABLE"}.get(error.errno, "SSH_NETWORK_UNAVAILABLE")
        raise Denied(code) from None
    except asyncssh.Error:
        raise Denied("SSH_CONNECTION_FAILED") from None
    return parse_probe(output, version, now=int(time.time()))


def parse_probe(output, version, *, now):
    # Arbitrary third-party stdout/stderr is never a public result, log payload or exception message.
    try:
        value = decode(output.rstrip(b"\n"))
    except Denied:
        raise Denied("SSH_UNSUPPORTED_OUTPUT") from None
    names = ("v", "uid", "boot_id", "observed_at")
    extra = {1: (), 2: ("software",), 3: ("software", "docker")}.get(version)
    if extra is None:
        raise Denied("SSH_PROBE_INVALID")
    fields(value, names + extra)
    if type(value["v"]) is not int or value["v"] != version or type(value["uid"]) is not int or value["uid"] != 0:
        raise Denied("SSH_PROBE_INVALID")
    text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    integer(value["observed_at"], now - 300, now + 2)
    result = {"status": "REACHABLE", "source": "restricted_helper", "observed_at": value["observed_at"], "boot_id": value["boot_id"]}
    if version >= 2:
        result["software"] = software_summary(value["software"])
    if version == 3:
        result["docker"] = docker_summary(value["docker"])
    return result


def provision_known_hosts(path, policy):
    new_private_file(path, "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode())


def verify_known_hosts(path, policy):
    expected = "".join(f"ho-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode()
    if protected_bytes(path, owner=os.geteuid(), exact_mode=0o600) != expected:
        raise Denied("SSH_PINNED_KEYS_INVALID")
