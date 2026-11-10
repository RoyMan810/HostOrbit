"""Exercise Controller SFTP transport against a disposable local OpenSSH server."""

import hashlib
import os
from pathlib import Path
from platform import freedesktop_os_release
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from hostorbit.errors import Denied
from hostorbit.runtime.sftp_publication import publish
from sftp_publication import listen, sftp_receiver


def main():
    if (sys.argv[1:] != ["--isolated-vm"] or os.geteuid() != 0
            or (freedesktop_os_release().get("ID"), freedesktop_os_release().get("VERSION_ID")) != ("ubuntu", "24.04")):
        raise SystemExit("Run as root in a disposable Ubuntu 24.04 VM with --isolated-vm.")
    with TemporaryDirectory(prefix="hostorbit-runtime-sftp-", dir="/run") as directory:
        root = Path(directory)
        with sftp_receiver(root) as receiver:
            key = root / "client"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            receiver.authorize(key.with_suffix(".pub").read_text())
            private = key.read_bytes()
            ciphertext = root / "controller.age"
            ciphertext.write_bytes(os.urandom(1024 * 1024))
            claims = {"ciphertext_size": ciphertext.stat().st_size,
                      "ciphertext_sha256": hashlib.sha256(ciphertext.read_bytes()).hexdigest()}
            provenance = b"fixture signed provenance"
            snapshot = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
            with listen(receiver.config, root / "sshd.log") as port:
                target = SimpleNamespace(value={"id": "01JCYQZ4T9V8MNVYEH3D2M7Q1B", "directory": "/store",
                                                "ip": "127.0.0.1", "port": port, "username": receiver.account,
                                                "host_key": receiver.host_key}, digest="a" * 64)
                result = publish(target, snapshot, ciphertext, claims, provenance, lambda: private)
                assert result["verified"] and (receiver.store / snapshot / "controller.age").read_bytes() == ciphertext.read_bytes()
                assert publish(target, snapshot, ciphertext, claims, provenance, lambda: private)["verified"]
                (receiver.store / snapshot / "controller.age").write_bytes(b"corrupt")
                try:
                    publish(target, snapshot, ciphertext, claims, provenance, lambda: private)
                except Denied as error:
                    assert error.code == "SFTP_READBACK_MISMATCH"
                else:
                    raise AssertionError("Corrupt final archive was accepted")
                wrong = SimpleNamespace(value={**target.value, "host_key": key.with_suffix(".pub").read_text()}, digest=target.digest)
                try:
                    publish(wrong, "01JCYQZ4T9V8MNVYEH3D2M7Q1C", ciphertext, claims, provenance, lambda: private)
                except Denied as error:
                    assert error.code == "SFTP_HOST_KEY_MISMATCH"
                else:
                    raise AssertionError("Wrong SSH server key was accepted")
                calls = 0
                def revoked():
                    nonlocal calls
                    calls += 1
                    if calls > 3:
                        raise Denied("FIXTURE_CREDENTIAL_REVOKED")
                    return private
                revoked_snapshot = "01JCYQZ4T9V8MNVYEH3D2M7Q1D"
                try:
                    publish(target, revoked_snapshot, ciphertext, claims, provenance, revoked)
                except Denied as error:
                    assert error.code == "FIXTURE_CREDENTIAL_REVOKED"
                else:
                    raise AssertionError("Revoked credential was accepted")
                assert not (receiver.store / revoked_snapshot).exists()
            print("Controller SFTP passed upload, fsync, readback, retry, corruption, host-key and revocation checks.")


if __name__ == "__main__":
    main()
