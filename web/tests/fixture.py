"""Loopback-only, disposable HTTPS Controller for browser tests."""

from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Literal

from starlette.staticfiles import StaticFiles
import uvicorn
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from hostorbit.api import create_app
from hostorbit.auth import AuthService
from hostorbit.config import Settings
from hostorbit.database import Store, identifier
from hostorbit.queue import JobQueue


ORIGIN = "https://127.0.0.1:4173"
PASSWORD = "HostOrbit fixture password!"
TARGETS = ["01JCYQZ4T9V8MNVYEH3D2M7Q1" + suffix for suffix in "ABC"]


def fixture(directory):
    store = Store.initialize(directory / "app.sqlite3")
    auth = AuthService(store)
    auth.create_owner(auth.issue_bootstrap(), "fixture-owner", PASSWORD)
    tokens, _ = auth.login("fixture-owner", PASSWORD, ip="fixture", correlation=identifier())
    _, version = auth.list_users(tokens.session)
    auth.create_user(tokens.session, tokens.csrf, "fixture-operator", PASSWORD, "Operator",
                     [{"permission": "vps:read", "resource_id": TARGETS[0]}],
                     if_match=version, correlation=identifier())
    queue = JobQueue(store)
    for target in TARGETS:
        queue.register_resource(target, "a" * 64, 1)
    for index, age in enumerate((0, 600)):
        queue.enqueue_probe(auth, tokens.session, tokens.csrf, TARGETS[index], identifier())
        claim, row = queue.claim(identifier())
        queue.advance(claim, "INTENT_PREPARED", permit={"claims": queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            queue.advance(claim, state)
        result = {"status": "REACHABLE", "source": "restricted_helper", "observed_at": int(time.time()) - age,
                  "boot_id": "11111111-1111-1111-1111-111111111111"}
        if index == 0:
            result["software"] = {"docker": "PRESENT", "nginx": "NOT_DETECTED"}
        queue.finish(claim, "SUCCEEDED", "PROBE_VERIFIED", result=result)

    app = create_app(Settings(store.path, ORIGIN), auth=auth)

    @app.post("/__fixture__/resources/{resource_id}/disable", status_code=204)
    def disable_resource(resource_id: str):
        with store.write() as db:
            db.execute("UPDATE resources SET enabled=0 WHERE id=?", (resource_id,))

    @app.post("/__fixture__/jobs/{job_id}/finish", status_code=204)
    def finish_job(job_id: str, outcome: Literal["SUCCEEDED", "UNKNOWN_OUTCOME"]):
        # Advance the actual durable queue in the disposable browser fixture.
        with store.read() as db:
            queued = db.execute(
                "SELECT id FROM jobs WHERE status='QUEUED' AND claimed_by IS NULL ORDER BY created_at,id LIMIT 1"
            ).fetchone()
        if queued is None or queued["id"] != job_id:
            raise HTTPException(409)
        claim, row = queue.claim(identifier())
        queue.advance(claim, "INTENT_PREPARED", permit={"claims": queue.binding(row)})
        for state in ("DISPATCHING", "EXECUTING", "VERIFYING"):
            queue.advance(claim, state)
        if outcome == "SUCCEEDED":
            queue.finish(claim, outcome, "PROBE_VERIFIED", result={
                "status": "REACHABLE", "source": "restricted_helper", "observed_at": int(time.time()),
                "boot_id": "11111111-1111-1111-1111-111111111111",
            })
        else:
            queue.finish(claim, outcome, "SSH_CONNECTION_LOST")

    app.mount("/", StaticFiles(directory=Path(__file__).resolve().parents[1] / "dist", html=True))
    return app


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="hostorbit-web-test-") as directory:
        root = Path(directory)
        key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        uvicorn.run(fixture(root), host="127.0.0.1", port=4173, ssl_keyfile=key, ssl_certfile=cert,
                    proxy_headers=False, access_log=False, log_level="warning")
