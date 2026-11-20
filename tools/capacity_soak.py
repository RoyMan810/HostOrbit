"""Run a disposable, in-process Controller API and SQLite capacity workload."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from importlib.metadata import version
from math import ceil
import os
from pathlib import Path
import platform
import secrets
import shutil
import sqlite3
import sys
import tempfile
from threading import Lock
import time

from fastapi.testclient import TestClient

from vpn_orbit.api import create_app
from vpn_orbit.auth import COOKIE, AuthService
from vpn_orbit.config import Settings
from vpn_orbit.database import Store, identifier
from vpn_orbit.queue import JobQueue


ORIGIN = "https://capacity.vpn-orbit.test"
HOSTS = 25
SERVICES_PER_HOST = 8
HISTORY_DAYS = 30
READ_P95_MS = 500
READ_CONCURRENCY = 4
WARMUP_SECONDS = 1800
SOAK_SECONDS = 28800
ENDPOINTS = {
    "inventory": "/api/v1/resources?limit=25",
    "detail": "/api/v1/resources/{target}",
    "audit": "/api/v1/audit",
    "session": "/api/v1/auth/session",
}


class MeasuredStore(Store):
    """Measure fixture transactions through the production Store implementation."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reset_metrics()
        self.metrics_lock = Lock()

    def reset_metrics(self):
        self.metrics = {
            "begin": Counter(), "transaction": Counter(), "commit": Counter(),
        }
        self.sqlite_errors = Counter()

    @contextmanager
    def write(self, *, kind="business"):
        started = time.monotonic()
        try:
            with super().write(kind=kind) as database:
                entered = time.monotonic()
                yield database
                committing = time.monotonic()
        except sqlite3.Error as error:
            with self.metrics_lock:
                self.sqlite_errors[error.sqlite_errorname or type(error).__name__] += 1
            raise
        else:
            elapsed = time.monotonic()
            with self.metrics_lock:
                for name, duration in (("begin", entered - started), ("transaction", elapsed - entered),
                                       ("commit", elapsed - committing)):
                    self.metrics[name][ceil(duration * 1000)] += 1


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
    started = time.monotonic()
    result = {"seconds": seconds, "elapsed_seconds": 0.0, "read_latency_ms": {}, "unexpected_http": 0,
              "secret_canaries_found": 0, "wal_peak_bytes": 0, "writer_count": 0, "writer_max_ms": 0,
              "writer_errors": 0}
    if seconds == 0:
        return result
    errors = Counter()
    latencies = {}
    queue = JobQueue(store)
    store.reset_metrics()

    def read(name, target):
        start = time.monotonic()
        response = client.get(ENDPOINTS[name].format(target=target))
        elapsed = ceil((time.monotonic() - start) * 1000)
        secrets_found = password in response.text or client.cookies[COOKIE] in response.text
        return name, min(elapsed, 10001), response.status_code, secrets_found

    stop = started + seconds
    targets = tuple(inventory)
    with ThreadPoolExecutor(max_workers=READ_CONCURRENCY) as pool:
        while time.monotonic() < stop:
            target = targets[result["writer_count"] % len(targets)]
            requests = [pool.submit(read, name, target) for name in ENDPOINTS]
            writer_start = time.monotonic()
            try:
                observe(queue, auth, tokens, target, inventory[target])
            except sqlite3.Error:
                result["writer_errors"] += 1
            else:
                result["writer_count"] += 1
                result["writer_max_ms"] = max(result["writer_max_ms"], ceil((time.monotonic() - writer_start) * 1000))
            for request in requests:
                name, elapsed, status, leaked = request.result()
                result["unexpected_http"] += status != 200
                result["secret_canaries_found"] += leaked
                if status == 200:
                    latencies.setdefault(name, Counter())[elapsed] += 1
                else:
                    errors[str(status)] += 1
            wal = store.path.with_name(store.path.name + "-wal")
            try:
                result["wal_peak_bytes"] = max(result["wal_peak_bytes"], wal.stat().st_size)
            except FileNotFoundError:
                pass
            if result["writer_errors"]:
                break
            time.sleep(max(0, min(interval, stop - time.monotonic())))
    result.update(
        elapsed_seconds=round(time.monotonic() - started, 3),
        read_latency_ms={name: summary(buckets) for name, buckets in latencies.items()},
        unexpected_statuses=dict(errors),
        sqlite_errors=dict(store.sqlite_errors),
        sqlite_write_latency_ms={name: summary(buckets) for name, buckets in store.metrics.items()},
    )
    return result


def summary(buckets):
    return {"count": sum(buckets.values()), "p95": percentile(buckets, .95), "p99": percentile(buckets, .99)}


def api_quota(client):
    # This runs before warmup, against a separate account with a fresh budget.
    outcomes = Counter()
    rejection = None
    for _ in range(121):
        response = client.get(ENDPOINTS["session"])
        outcomes[str(response.status_code)] += 1
        if response.status_code == 429:
            rejection = {"code": response.json().get("code"), "retry_after": response.headers.get("retry-after")}
    expected = outcomes == {"200": 120, "429": 1} and rejection == {"code": "API_RATE_LIMIT", "retry_after": "60"}
    return {"passed": expected, "http_statuses": dict(outcomes), "rejection": rejection}


def environment(directory):
    release = platform.freedesktop_os_release() if platform.system() == "Linux" else {}
    return {
        "os": release.get("PRETTY_NAME", platform.system()), "kernel": platform.release(),
        "available_vcpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count(),
        "ram_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") if platform.system() == "Linux" else None,
        "work_filesystem_bytes": shutil.disk_usage(directory).total,
        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version, "fastapi": version("fastapi"),
    }


def run(directory, *, warmup, seconds, interval, check_quota=False):
    started_utc = datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-capacity-", dir=directory) as workspace:
        store = MeasuredStore.initialize(Path(workspace) / "controller.sqlite3")
        auth = AuthService(store)
        password = secrets.token_urlsafe(36)
        auth.create_owner(auth.issue_bootstrap(), "capacity-owner", password)
        tokens, _ = auth.login("capacity-owner", password, ip="fixture", correlation=identifier())
        inventory = seed(store, auth, tokens)
        app = create_app(Settings(store.path, ORIGIN), auth=auth)
        quota = None
        if check_quota:
            username = "capacity-quota-auditor"
            _, user_version = auth.list_users(tokens.session)
            auth.create_user(tokens.session, tokens.csrf, username, password, "Auditor", [],
                             if_match=user_version, correlation=identifier())
            quota_tokens, _ = auth.login(username, password, ip="fixture", correlation=identifier())
            with TestClient(app, base_url=ORIGIN) as quota_client:
                quota_client.cookies.set(COOKIE, quota_tokens.session)
                quota = api_quota(quota_client)
                auth.logout(quota_tokens.session, quota_tokens.csrf, correlation=identifier())
        with store.connect() as observer, TestClient(app, base_url=ORIGIN) as client:
            client.cookies.set(COOKIE, tokens.session)
            warmup_result = phase(client, store, auth, tokens, inventory, password, warmup, interval)
            measured = phase(client, store, auth, tokens, inventory, password, seconds, interval)
            events = store.verify_audit()
            audit_canaries = observer.execute(
                "SELECT count(*) FROM audit WHERE instr(details, ?) OR instr(details, ?)",
                (password, tokens.session),
            ).fetchone()[0]
            checkpoint_start = time.monotonic()
            busy, log_frames, checkpointed_frames = observer.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            checkpoint_ms = ceil((time.monotonic() - checkpoint_start) * 1000)
            integrity = observer.execute("PRAGMA integrity_check").fetchone()[0]
        read_pass = all(metric["p95"] <= READ_P95_MS for metric in measured["read_latency_ms"].values())
        success = (len(measured["read_latency_ms"]) == len(ENDPOINTS) and read_pass and integrity == "ok"
                   and audit_canaries == 0 and (quota is None or quota["passed"])
                   and all(not result[key] for result in (warmup_result, measured)
                           for key in ("unexpected_http", "secret_canaries_found", "writer_errors")))
        return {"status": "WORKLOAD_PASSED" if success else "WORKLOAD_FAILED",
                "profile": "synthetic_in_process", "release_acceptance": False, "hosts": HOSTS,
                "services": HOSTS * SERVICES_PER_HOST, "history_days": HISTORY_DAYS,
                "started_at_utc": started_utc, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                "environment": environment(directory), "read_concurrency": READ_CONCURRENCY, "interval_seconds": interval,
                "full_duration": warmup_result["elapsed_seconds"] >= WARMUP_SECONDS
                and measured["elapsed_seconds"] >= SOAK_SECONDS,
                "warmup": warmup_result, "measured": measured, "api_user_quota": quota,
                "audit": events, "audit_canary_rows": audit_canaries, "sqlite_integrity": integrity,
                "wal_checkpoint": {"busy": busy, "duration_ms": checkpoint_ms, "log_frames": log_frames,
                                   "checkpointed_frames": checkpointed_frames}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path.cwd(), help="Parent of the disposable SQLite database")
    parser.add_argument("--warmup", type=int, default=WARMUP_SECONDS)
    parser.add_argument("--seconds", type=int, default=SOAK_SECONDS)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--check-quota", action="store_true", help="Check the exact API user budget before warmup")
    args = parser.parse_args()
    if not 0 <= args.warmup <= WARMUP_SECONDS or not 1 <= args.seconds <= SOAK_SECONDS or not 2.5 <= args.interval <= 60:
        parser.error("Use at most 30 minutes of warmup and eight hours of measurement, interval 2.5–60 seconds.")
    result = run(args.work_dir, warmup=args.warmup, seconds=args.seconds, interval=args.interval,
                 check_quota=args.check_quota)
    print(json.dumps(result, sort_keys=True))
    return result["status"] != "WORKLOAD_PASSED"


if __name__ == "__main__":
    sys.exit(main())
