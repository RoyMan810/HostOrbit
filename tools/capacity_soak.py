"""Run a disposable, in-process Controller API and SQLite capacity workload."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from math import ceil
from pathlib import Path
import secrets
import sys
import tempfile
import time

from fastapi.testclient import TestClient

from hostorbit.api import create_app
from hostorbit.auth import COOKIE, AuthService
from hostorbit.config import Settings
from hostorbit.database import Store, identifier
from hostorbit.queue import JobQueue


ORIGIN = "https://capacity.hostorbit.test"
HOSTS = 25
SERVICES_PER_HOST = 8
HISTORY_DAYS = 30
READ_P95_MS = 500


def observe(queue, auth, tokens, target, containers):
    queue.enqueue_probe(auth, tokens.session, tokens.csrf, target, identifier())
    claim, row = queue.claim(identifier())
    queue.advance(claim, "INTENT_PREPARED", permit={"claims": queue.binding(row)})
    for status in ("DISPATCHING", "EXECUTING", "VERIFYING"):
        queue.advance(claim, status)
    queue.finish(claim, "SUCCEEDED", "PROBE_VERIFIED", result={
        "status": "REACHABLE", "source": "restricted_helper", "observed_at": int(queue.clock()),
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
        "docker": {"status": "OBSERVED", "containers": containers},
    })


def seed(store, auth, tokens):
    queue = JobQueue(store)
    inventory = {}
    for index in range(HOSTS):
        target = identifier()
        queue.register_resource(target, hashlib.sha256(target.encode()).hexdigest(), 1)
        inventory[target] = [
            {"id": hashlib.sha256(f"{index}/{service}".encode()).hexdigest(), "project": "capacity",
             "service": f"fixture-{service}", "state": "RUNNING", "published_ports": []}
            for service in range(SERVICES_PER_HOST)
        ]
    now = int(time.time())
    for day in range(HISTORY_DAYS, 0, -1):
        clock = now - day * 86400
        historical = JobQueue(store, clock=lambda: clock)
        for target, containers in inventory.items():
            observe(historical, auth, tokens, target, containers)
    return inventory


def percentile(buckets, fraction):
    threshold = sum(buckets.values()) * fraction
    cumulative = 0
    for latency, count in sorted(buckets.items()):
        cumulative += count
        if cumulative >= threshold:
            return latency
    return None


def phase(client, store, auth, tokens, inventory, password, seconds, interval):
    result = {"seconds": seconds, "read_latency_ms": {}, "unexpected_http": 0, "secret_canaries_found": 0,
              "wal_peak_bytes": 0, "writer_count": 0, "writer_max_ms": 0}
    if seconds == 0:
        return result
    latencies = {}
    queue = JobQueue(store)
    endpoints = {
        "inventory": "/api/v1/resources?limit=25",
        "detail": "/api/v1/resources/{target}",
        "audit": "/api/v1/audit",
        "session": "/api/v1/auth/session",
    }

    def read(name, target):
        start = time.monotonic()
        response = client.get(endpoints[name].format(target=target))
        elapsed = ceil((time.monotonic() - start) * 1000)
        secrets_found = password in response.text or client.cookies[COOKIE] in response.text
        return name, min(elapsed, 10001), response.status_code, secrets_found

    stop = time.monotonic() + seconds
    targets = tuple(inventory)
    with ThreadPoolExecutor(max_workers=4) as pool:
        while time.monotonic() < stop:
            target = targets[result["writer_count"] % len(targets)]
            requests = [pool.submit(read, name, target) for name in endpoints]
            writer_start = time.monotonic()
            observe(queue, auth, tokens, target, inventory[target])
            result["writer_count"] += 1
            result["writer_max_ms"] = max(result["writer_max_ms"], ceil((time.monotonic() - writer_start) * 1000))
            for request in requests:
                name, elapsed, status, leaked = request.result()
                result["unexpected_http"] += status != 200
                result["secret_canaries_found"] += leaked
                if status == 200:
                    latencies.setdefault(name, Counter())[elapsed] += 1
            wal = store.path.with_name(store.path.name + "-wal")
            try:
                result["wal_peak_bytes"] = max(result["wal_peak_bytes"], wal.stat().st_size)
            except FileNotFoundError:
                pass
            time.sleep(max(0, min(interval, stop - time.monotonic())))
    for name, buckets in latencies.items():
        result["read_latency_ms"][name] = {"count": sum(buckets.values()), "p95": percentile(buckets, .95),
                                           "p99": percentile(buckets, .99)}
    return result


def run(directory, *, warmup, seconds, interval):
    with tempfile.TemporaryDirectory(prefix="hostorbit-capacity-", dir=directory) as workspace:
        store = Store.initialize(Path(workspace) / "controller.sqlite3")
        auth = AuthService(store)
        password = secrets.token_urlsafe(36)
        auth.create_owner(auth.issue_bootstrap(), "capacity-owner", password)
        tokens, _ = auth.login("capacity-owner", password, ip="fixture", correlation=identifier())
        inventory = seed(store, auth, tokens)
        with (store.connect() as observer,
              TestClient(create_app(Settings(store.path, ORIGIN), auth=auth), base_url=ORIGIN) as client):
            client.cookies.set(COOKIE, tokens.session)
            warmup_result = phase(client, store, auth, tokens, inventory, password, warmup, interval)
            measured = phase(client, store, auth, tokens, inventory, password, seconds, interval)
            events = store.verify_audit()
            _, log_frames, checkpointed_frames = observer.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            integrity = observer.execute("PRAGMA integrity_check").fetchone()[0]
        read_pass = all(metric["p95"] <= READ_P95_MS for metric in measured["read_latency_ms"].values())
        success = (len(measured["read_latency_ms"]) == 4 and read_pass and integrity == "ok"
                   and all(not result[key] for result in (warmup_result, measured)
                           for key in ("unexpected_http", "secret_canaries_found")))
        return {"status": "WORKLOAD_PASSED" if success else "WORKLOAD_FAILED",
                "profile": "synthetic_in_process", "release_acceptance": False, "hosts": HOSTS,
                "services": HOSTS * SERVICES_PER_HOST, "history_days": HISTORY_DAYS,
                "warmup": warmup_result, "measured": measured,
                "audit": events, "sqlite_integrity": integrity,
                "wal_checkpoint": {"log_frames": log_frames, "checkpointed_frames": checkpointed_frames}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path.cwd(), help="Parent of the disposable SQLite database")
    parser.add_argument("--warmup", type=int, default=1800)
    parser.add_argument("--seconds", type=int, default=28800)
    parser.add_argument("--interval", type=float, default=3.0)
    args = parser.parse_args()
    if not 0 <= args.warmup <= 1800 or not 1 <= args.seconds <= 28800 or not 2.5 <= args.interval <= 60:
        parser.error("Use at most 30 minutes of warmup and eight hours of measurement, interval 2.5–60 seconds.")
    result = run(args.work_dir, warmup=args.warmup, seconds=args.seconds, interval=args.interval)
    print(json.dumps(result, sort_keys=True))
    return result["status"] != "WORKLOAD_PASSED"


if __name__ == "__main__":
    sys.exit(main())
