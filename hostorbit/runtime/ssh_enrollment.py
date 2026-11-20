"""One credential check against an already approved SSH endpoint."""

import asyncio
import secrets

import asyncssh

from ..errors import Denied


class EnrollmentClient(asyncssh.SSHClient):
    def __init__(self, password, key):
        self.password, self.key = password, key
        self.offered = False

    def password_auth_requested(self):
        password, self.password = self.password, None
        self.offered |= password is not None
        return password

    def public_key_auth_requested(self):
        key, self.key = self.key, None
        self.offered |= key is not None
        return [key] if key is not None else None


def verify_credentials(target, username, *, password, private_key):
    try:
        host_key = asyncssh.import_public_key(target["host_key"])
    except (asyncssh.KeyImportError, ValueError):
        raise Denied("ENROLLMENT_TARGET_UNAVAILABLE", 404) from None
    if not secrets.compare_digest(host_key.get_fingerprint("sha256"), target["fingerprint"]):
        raise Denied("ENROLLMENT_TARGET_UNAVAILABLE", 404)

    try:
        key = asyncssh.import_private_key(private_key) if private_key is not None else None
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED", 422) from None

    client = EnrollmentClient(password, key)

    async def check():
        async with asyncssh.connect(
            target["ip"], port=target["port"], username=username, client_factory=lambda: client,
            config=None, known_hosts=([host_key], [], []), server_host_key_algs=["ssh-ed25519"],
            client_keys=None, agent_path=None, agent_forwarding=False,
            preferred_auth=["publickey" if key is not None else "password"],
            public_key_auth=key is not None, password_auth=password is not None,
            kbdint_auth=False, gss_auth=False, gss_kex=False, host_based_auth=False,
            x509_trusted_certs=None, x509_trusted_cert_paths=[], connect_timeout=4, login_timeout=5,
        ):
            # Servers may permit login without any authentication.
            if not client.offered:
                raise Denied("SSH_AUTHENTICATION_FAILED", 424)

    async def bounded():
        await asyncio.wait_for(check(), 8)

    try:
        asyncio.run(bounded())
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("HOST_FINGERPRINT_MISMATCH", 412) from None
    except asyncssh.PermissionDenied:
        raise Denied("SSH_AUTHENTICATION_FAILED", 424) from None
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied("SSH_CONNECTION_FAILED", 502) from None
