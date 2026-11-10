"""Bounded SFTP publication: exclusive staging, readback, fsync, final promotion.

No shell/exec channel, recursive upload, overwrite or remote deletion exists.
Only ciphertext, its signed provenance and a completion marker are transferred.
"""

import asyncio
import hashlib
import io
import os
from pathlib import PurePosixPath
import stat

import asyncssh

from ..errors import Denied
from .protocol import ULID, canonical, checksum, integer, text
from .ssh import validate_private_key


def publication_timeout(size):
    integer(size, 200, 4 * 1024**3)
    # Upload plus two readbacks at a minimum of 1 MiB/s, with setup allowance.
    return 120 + (3 * size + 1024**2 - 1) // 1024**2


def completion(target, snapshot_id, claims, provenance):
    text(snapshot_id, ULID)
    return {"v": 1, "type": "hostorbit.sftp.publication", "snapshot_id": snapshot_id,
            "target_id": target.value["id"], "target_digest": target.digest,
            "ciphertext_sha256": claims["ciphertext_sha256"], "ciphertext_size": claims["ciphertext_size"],
            "provenance_sha256": hashlib.sha256(provenance).hexdigest()}


async def _directory(client, path):
    parts = PurePosixPath(path).parts
    current = ""
    for part in parts[1:]:
        current += "/" + part
        attrs = await client.lstat(current)
        if attrs.permissions is None or not stat.S_ISDIR(attrs.permissions):
            raise Denied("SFTP_DIRECTORY_UNTRUSTED")


async def _readback(client, remote, expected_size, expected_digest, check):
    attrs = await client.lstat(remote)
    if (attrs.permissions is None or not stat.S_ISREG(attrs.permissions) or attrs.size != expected_size):
        raise Denied("SFTP_READBACK_MISMATCH")
    digest, size = hashlib.sha256(), 0
    async with client.open(remote, "rb", encoding=None) as stream:
        while data := await asyncio.wait_for(stream.read(min(65536, expected_size + 1 - size)), 30):
            check()
            digest.update(data)
            size += len(data)
            if size > expected_size:
                raise Denied("SFTP_READBACK_MISMATCH")
    if size != expected_size or digest.hexdigest() != expected_digest:
        raise Denied("SFTP_READBACK_MISMATCH")


async def _put(client, remote, source, size, expected_digest, check):
    digest, written = hashlib.sha256(), 0
    async with client.open(remote, "xb", attrs=asyncssh.SFTPAttrs(permissions=0o600), encoding=None) as stream:
        while data := source.read(65536):
            check()
            written += len(data)
            if written > size:
                raise Denied("SFTP_LOCAL_SOURCE_CHANGED")
            digest.update(data)
            await asyncio.wait_for(stream.write(data), 30)
        if written != size or digest.hexdigest() != expected_digest:
            raise Denied("SFTP_LOCAL_SOURCE_CHANGED")
        # Unsupported persistence is an error, never a silent fallback.
        await asyncio.wait_for(stream.fsync(), 30)
    await _readback(client, remote, size, expected_digest, check)


async def publish_session(client, target, snapshot_id, ciphertext, claims, provenance, check):
    """Protocol also exercised with fault-injecting contract tests."""
    check()
    await _directory(client, target.value["directory"])
    final = target.value["directory"] + "/" + text(snapshot_id, ULID)
    marker = canonical(completion(target, snapshot_id, claims, provenance))
    files = [("controller.age", claims["ciphertext_size"], claims["ciphertext_sha256"]),
             ("provenance.json", len(provenance), hashlib.sha256(provenance).hexdigest()),
             ("COMPLETE", len(marker), hashlib.sha256(marker).hexdigest())]

    async def verify_final():
        await _directory(client, final)
        names = set(await client.listdir(final)) - {".", ".."}
        if names != {item[0] for item in files}:
            raise Denied("SFTP_FINAL_INCOMPLETE")
        for name, size, digest in files:
            check()
            await _readback(client, final + "/" + name, size, digest, check)

    try:
        await client.lstat(final)
    except asyncssh.SFTPNoSuchFile:
        pass
    else:
        # Lost final ACK/retry: verify exactly the same object, never replace it.
        await verify_final()
        return {**completion(target, snapshot_id, claims, provenance), "marker_sha256": checksum(completion(target, snapshot_id, claims, provenance)),
                "remote_path": final, "verified": True}
    staging = target.value["directory"] + "/." + snapshot_id + "." + os.urandom(8).hex() + ".partial"
    await client.mkdir(staging, attrs=asyncssh.SFTPAttrs(permissions=0o700))
    with open(ciphertext, "rb") as source:
        await _put(client, staging + "/controller.tmp", source, files[0][1], files[0][2], check)
    check()
    await client.rename(staging + "/controller.tmp", staging + "/controller.age")
    await _put(client, staging + "/provenance.tmp", io.BytesIO(provenance), files[1][1], files[1][2], check)
    await client.rename(staging + "/provenance.tmp", staging + "/provenance.json")
    check()
    await _put(client, staging + "/complete.tmp", io.BytesIO(marker), files[2][1], files[2][2], check)
    await client.rename(staging + "/complete.tmp", staging + "/COMPLETE")
    # Only this last non-overwriting directory rename exposes a completed ID.
    # Partial directories are never eligible, even if they contain a marker.
    check()
    await client.rename(staging, final)
    await verify_final()
    return {**completion(target, snapshot_id, claims, provenance), "marker_sha256": hashlib.sha256(marker).hexdigest(),
            "remote_path": final, "verified": True}


async def _connect_and_publish(target, snapshot_id, ciphertext, claims, provenance, credential):
    def check():
        # Re-authenticate protected Vault metadata/AAD at each safe checkpoint.
        # Revocation cannot cryptographically undo an already authenticated SSH
        # session, but it can prevent final publication of this attempt.
        credential()

    key = validate_private_key(credential())
    host_key = asyncssh.import_public_key(target.value["host_key"])
    connection = await asyncssh.connect(
        target.value["ip"], port=target.value["port"], username=target.value["username"],
        client_keys=[key], agent_path=None, config=None, known_hosts=([host_key], [], []),
        x509_trusted_certs=None, x509_trusted_cert_paths=[], preferred_auth=["publickey"],
        password_auth=False, kbdint_auth=False, gss_auth=False, gss_kex=False, host_based_auth=False,
        server_host_key_algs=["ssh-ed25519"], agent_forwarding=False, connect_timeout=4, login_timeout=5,
    )
    try:
        async with connection.start_sftp_client(env={}, send_env=[]) as client:
            return await publish_session(client, target, snapshot_id, ciphertext, claims, provenance, check)
    finally:
        connection.close()
        try:
            await asyncio.wait_for(connection.wait_closed(), 1)
        except asyncio.TimeoutError:
            connection.abort()


def publish(target, snapshot_id, ciphertext, claims, provenance, credential):
    async def bounded():
        return await asyncio.wait_for(_connect_and_publish(target, snapshot_id, ciphertext, claims, provenance, credential),
                                      publication_timeout(claims["ciphertext_size"]))
    try:
        return asyncio.run(bounded())
    except Denied:
        raise
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("SFTP_HOST_KEY_MISMATCH") from None
    except asyncssh.PermissionDenied:
        raise Denied("SFTP_AUTHENTICATION_FAILED") from None
    except asyncssh.SFTPOpUnsupported:
        raise Denied("SFTP_PERSISTENCE_UNSUPPORTED") from None
    except asyncssh.ConnectionLost:
        raise Denied("SFTP_CONNECTION_LOST") from None
    except (asyncio.TimeoutError, TimeoutError):
        raise Denied("SFTP_TIMEOUT") from None
    except asyncssh.SFTPError:
        raise Denied("SFTP_REMOTE_FAILED") from None
    except asyncssh.Error:
        raise Denied("SFTP_CONNECTION_FAILED") from None
    except OSError:
        raise Denied("SFTP_NETWORK_OR_STORAGE_UNAVAILABLE") from None
