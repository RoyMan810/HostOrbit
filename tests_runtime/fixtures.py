import base64
from functools import lru_cache
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from hostorbit.runtime.policy import Policy


TARGET = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
OTHER = "01JCYQZ4T9V8MNVYEH3D2M7Q1B"
SECRET = "01JCYQZ4T9V8MNVYEH3D2M7Q1C"
ACTOR = "01JCYQZ4T9V8MNVYEH3D2M7Q1D"
WORKER_UID = 11001
BROKER_UID = 11002
PASSWORD = "Fixture-Owner-password-117!"


def public_key():
    raw = struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 32) + b"k" * 32
    return "ssh-ed25519 " + base64.b64encode(raw).decode()


@lru_cache
def private_key():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(p)], check=True, capture_output=True)
        return p.read_bytes()


def policy(*, capabilities=None):
    return Policy([{"id": TARGET, "ip": "10.222.0.2", "port": 2222, "allowed_cidrs": ["10.222.0.0/24"],
                    "host_key": public_key(), "secret_ref": SECRET + ":v1", "policy_revision": 1,
                    "dependencies": ["compose:shared"], "capabilities": capabilities or ["host.probe"]}])


def binding(p, job_id):
    return {"job_id": job_id, "plan_id": job_id, "revision": 1, "plan_digest": "a" * 64,
            "approval_id": job_id, "actor_id": ACTOR, "target": TARGET, "capability": p.targets[TARGET].value["capabilities"][0],
            "scope_digest": p.targets[TARGET].scope_digest}


def observation():
    return {"status": "REACHABLE", "source": "restricted_helper", "observed_at": int(time.time()), "boot_id": "12345678-1234-1234-1234-123456789abc"}
