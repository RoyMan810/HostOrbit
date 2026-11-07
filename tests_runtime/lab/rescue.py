"""Disposable one-host native recovery procedure fixture, not DR attestation.

Only an ephemeral CI Owner identity is accepted over stdin. The production
workstation profile is expected to refuse this already installed Controller.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from unittest.mock import patch

from hostorbit.admission import Admission
from hostorbit.auth import AuthService
from hostorbit.database import Store
from hostorbit.errors import Denied
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.policy import Policy
from hostorbit.runtime.protocol import checksum
from hostorbit.runtime.recovery_import import RecoveryTarget
from hostorbit.runtime.rescue import offline_profile, prepare_bundle, wipe


def main():
    if (sys.argv[1:] not in (["--isolated-vm"], ["--isolated-vm", "--keep-data"]) or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Recovery fixture requires an explicitly isolated GitHub-hosted VM")
    root = Path("/var/lib/hostorbit-rescue-lab")
    root.mkdir(mode=0o700)  # Refuse any pre-existing path.
    identity = None
    keep = False
    try:
        data = json.loads(sys.stdin.buffer.read(16384))
        identity = bytearray(base64.b64decode(data["identity"], validate=True))
        envelope = json.loads(Path(data["archive"]["provenance"]).read_bytes())
        anchor = Path(data["anchor"]).read_bytes()
        (root / "tools").mkdir(mode=0o700)
        keygen = root / "tools/age-keygen"
        keygen.write_bytes(Path(data["keygen"]).read_bytes())
        keygen.chmod(0o755)
        request = RecoveryTarget.issue(root / "target-state", root / "target-data", checksum(envelope), keygen_path=keygen)
        # Production preflight refuses this Controller before any Owner secret
        # is processed. The positive procedure uses a clearly labelled fixture.
        try:
            offline_profile()
        except Denied:
            pass
        else:
            raise RuntimeError("Installed Controller passed the offline-workstation profile")
        bundle = root / "recovery.age"
        with patch("hostorbit.runtime.rescue.offline_profile", return_value={"profile": "CI_PROCEDURE_FIXTURE_NOT_OFFLINE_ATTESTED"}):
            review = prepare_bundle(data["archive"]["ciphertext"], envelope, anchor, identity, request, bundle)
        if review["bundle_sha256"] != hashlib.sha256(bundle.read_bytes()).hexdigest():
            raise RuntimeError("Owner review did not bind the exact ciphertext")
        target = RecoveryTarget(root / "target-state")
        for digest, password, expected in (("0" * 64, data["password"], "OWNER_DIGEST_MISMATCH"),
                                           (review["bundle_sha256"], "wrong", "RECOVERY_OWNER_AUTH_REQUIRED")):
            try:
                target.accept(bundle, owner_digest=digest, username="roman", password=password)
            except Denied as error:
                if error.code != expected:
                    raise
            else:
                raise RuntimeError("Recovery skipped independent digest/Owner authentication")
        imported = target.accept(bundle, owner_digest=review["bundle_sha256"], username="roman", password=data["password"])
        if imported["status"] != "READ_ONLY_RECOVERY" or imported["services_installed"] or imported["restore_verified"]:
            raise RuntimeError("Data import falsely reported activation/installation/DR")
        destination = root / "target-data"
        admission = Admission(destination / "writer-admission")
        store = Store(destination / "app/controller.sqlite3", writers=admission)
        store.verify_audit()
        AuthService(store).login("roman", data["password"], ip="127.0.0.1", correlation="native-recovery-fixture")
        try:
            with store.write():
                pass
        except Denied as error:
            if error.code != "WRITER_ADMISSION_CLOSED":
                raise
        else:
            raise RuntimeError("Recovered app admitted a business mutation")
        (destination / "writer-admission/state.json").unlink()
        Coordinator(destination / "control-gate/snapshots", admission).recover()
        if admission.state()["phase"] != "READ_ONLY_RECOVERY":
            raise RuntimeError("Coordinator activated a recovered Controller")
        policy = Policy(json.loads((destination / "source/targets.json").read_bytes())["targets"])
        authority = Authority(destination / "control-gate", policy)
        try:
            authority.recover()
            with authority.journal.connect() as db:
                row = db.execute("SELECT * FROM gate").fetchone()
                if row["activated"] != 0 or row["instance_id"] != request["target_id"] or row["state"] != "RECOVERY_HOLD":
                    raise RuntimeError("Recovered authority reused old activation")
        finally:
            authority.close()
        if (destination / "gate.pub").read_bytes() == anchor:
            raise RuntimeError("Recovered authority reused its source signer")
        opened = subprocess.run(["/usr/bin/systemd-creds", "decrypt", "--name=broker-dek",
                                 str(destination / "credentials/broker-dek.cred"), "-"], capture_output=True, check=True).stdout
        from nacl.secret import Aead
        with sqlite3.connect(destination / "vault/vault.sqlite3") as db:
            for metadata, digest in db.execute("SELECT metadata,object_digest FROM secrets"):
                secret = Aead(opened).decrypt((destination / "vault/objects" / digest).read_bytes(), metadata.encode())
                if not secret.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
                    raise RuntimeError("New OS-sealed portable DEK did not restore Vault objects")
                del secret
        for path in destination.rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                if opened in raw or b"AGE-SECRET-KEY-" in raw:
                    raise RuntimeError("Recovery wrote a plaintext identity/DEK")
        try:
            RecoveryTarget(root / "target-state").accept(bundle, owner_digest=review["bundle_sha256"], username="roman", password=data["password"])
        except Denied as error:
            if error.code != "RECOVERY_REQUEST_CONSUMED":
                raise
        else:
            raise RuntimeError("Recovery request was reused")
        if (root / "target-state/identity.cred").exists():
            raise RuntimeError("Successful import retained the one-time identity")
        print("Native Rescue data import passed exact Owner digest, separate Owner auth, new host credential/signer, replay refusal and durable READ_ONLY_RECOVERY; offline profile and physical DR remain unattested.", flush=True)
        keep = "--keep-data" in sys.argv
    finally:
        if identity is not None:
            wipe(identity)
        if not keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
