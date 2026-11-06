"""Exercise forged approvals and protected Broker grants in separate containers."""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import sys
import time

from broker_probe import request


_PLAN = ("docker.restart", "managed-fixture", "fixture-ssh")
_APP = Path("/lab/app/plans.sqlite3")
_GRANT = Path("/lab/permit.json")
_ATTACKS = (
    ("arbitrary-shell", "exec", _PLAN[1], _PLAN[2], None, "INVALID_REQUEST"),
    ("plaintext-secret", "decrypt", _PLAN[1], _PLAN[2], None, "INVALID_REQUEST"),
    ("untyped-docker", "docker.raw", _PLAN[1], _PLAN[2], None, "INVALID_REQUEST"),
    ("foreign-resource", _PLAN[0], "foreign-fixture", _PLAN[2], None, "SCOPE_DENIED"),
    ("foreign-secret", _PLAN[0], _PLAN[1], "foreign-ssh", None, "SCOPE_DENIED"),
    ("forged-permit", *_PLAN, "forged", "SCOPE_DENIED"),
)


def encode(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def digest(data):
    return hashlib.sha256(encode(data)).hexdigest()


def issue(path):
    grant = {
        "operation": "use_for_scoped_ssh", "operation_id": "a04-fixture-restart",
        "plan_digest": digest(_PLAN), "resource": _PLAN[1], "secret_ref": _PLAN[2],
        "scope_digest": digest({"action": _PLAN[0], "resource": _PLAN[1], "ref": _PLAN[2]}),
        "permit": secrets.token_hex(32), "nonce": secrets.token_hex(16), "expires_at": int(time.time()) + 60,
    }
    path.write_bytes(encode(grant))
    path.chmod(0o644)


def assert_no_direct_access():
    with socket.socket(socket.AF_UNIX) as connection:
        try:
            connection.connect("/var/run/docker.sock")
        except (FileNotFoundError, PermissionError):
            pass
        else:
            raise RuntimeError("Direct Docker socket access was available")
    try:
        Path("/lab/policy/vault-canary").read_bytes()
    except (FileNotFoundError, PermissionError):
        return
    raise RuntimeError("The protected fixture Vault was readable")


def compromise_backend():
    if request(encode({"operation": "probe", "consumer_kind": "worker"})) != "NO_SOCKET":
        raise RuntimeError("The Backend could reach the Broker socket")
    assert_no_direct_access()
    if _GRANT.exists():
        raise RuntimeError("The Backend could read the supervisor grant")
    with closing(sqlite3.connect(_APP)) as db, db:
        db.execute("""CREATE TABLE plans (
            name TEXT PRIMARY KEY, action TEXT NOT NULL, resource TEXT NOT NULL,
            secret TEXT NOT NULL, approval TEXT NOT NULL, permit_override TEXT
        )""")
        db.execute("INSERT INTO plans VALUES ('in-scope', ?, ?, ?, 'DRAFT', NULL)", _PLAN)
    with closing(sqlite3.connect(_APP)) as db, db:
        if db.execute("UPDATE plans SET approval = 'APPROVED' WHERE approval = 'DRAFT'").rowcount != 1:
            raise RuntimeError("The forged approval did not replace a committed draft")
        db.executemany(
            "INSERT INTO plans VALUES (?, ?, ?, ?, 'APPROVED', ?)",
            (row[:-1] for row in _ATTACKS),
        )
    print("Backend wrote forged approvals and had no direct Broker, Vault or Docker access.")


def exercise_worker():
    assert_no_direct_access()
    grant = json.loads(_GRANT.read_bytes())
    with closing(sqlite3.connect(f"{_APP.as_uri()}?mode=ro", uri=True)) as db:
        plans = {
            name: (action, resource, secret, approval, override)
            for name, action, resource, secret, approval, override in db.execute("SELECT * FROM plans")
        }
    for name, expected in [(row[0], row[-1]) for row in _ATTACKS] + [("in-scope", "USE_GRANTED")]:
        action, resource, secret, approval, override = plans[name]
        if approval != "APPROVED":
            raise RuntimeError("Expected an apparently approved plan from the compromised Backend")
        frame = encode({
            **grant, "operation": "use_for_scoped_ssh" if action == _PLAN[0] else action,
            "resource": resource, "secret_ref": secret, "plan_digest": digest((action, resource, secret)),
            "permit": override if override is not None else grant["permit"],
        })
        response = request(frame)
        if response != expected:
            raise RuntimeError(f"{name}: expected {expected}, received {response}")
        print(f"{name}: {response}")
    if request(encode(grant)) != "PERMIT_REPLAY":
        raise RuntimeError("The Broker reused an already consumed grant")
    print("The scoped grant produced a receipt only. Replaying it was denied.")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "issue":
        issue(Path(sys.argv[2]))
    elif mode == "backend":
        compromise_backend()
    elif mode == "worker":
        exercise_worker()
    else:
        raise SystemExit("Unknown lab role")
