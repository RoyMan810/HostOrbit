"""Exercise an installed disposable Controller through HTTPS and real SSH observations."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import getpass
import json
from math import ceil
from pathlib import Path
import re
import secrets
import ssl
from threading import Barrier, BrokenBarrierError
import time
from urllib.parse import urlsplit

import httpx

from hostorbit.auth import COOKIE
from hostorbit.runtime.protocol import ULID
from tools.capacity_soak import (
    ENDPOINTS, HOSTS, READ_CONCURRENCY, READ_P95_MS, SERVICES_PER_HOST, SOAK_SECONDS, WARMUP_SECONDS,
    environment, summary,
)


class FixtureError(Exception):
    """An invalid fixture or request state with a safe reporting code."""


class Workload:
    def __init__(self, client, targets, password, csrf):
        self.client = client
        self.targets = targets
        self.csrf = csrf
        cookie = client.cookies.get(COOKIE)
        if not cookie:
            raise FixtureError("SESSION_COOKIE_MISSING")
        self.canaries = password, cookie
        self.pending = None
        self.next_target = 0

    def read(self, name, target):
        start = time.monotonic()
        try:
            response = self.client.get(ENDPOINTS[name].format(target=target))
        except httpx.TimeoutException:
            return name, 0, "timeout", False
        except httpx.RequestError:
            return name, 0, "transport", False
        leaked = any(secret in response.text for secret in self.canaries)
        return name, ceil((time.monotonic() - start) * 1000), str(response.status_code), leaked

    def probe_step(self, progress):
        in_flight = self.pending is not None
        target = self.targets[self.next_target]
        if in_flight:
            response = self.client.get(f"/api/v1/jobs/{self.pending}")
        else:
            response = self.client.post(
                ENDPOINTS["detail"].format(target=target) + "/observations",
                headers={"X-CSRF-Token": self.csrf, "Idempotency-Key": secrets.token_urlsafe(24)},
                json={},
            )
        if any(secret in response.text for secret in self.canaries):
            raise FixtureError("SECRET_CANARY_FOUND_IN_JOB_RESPONSE")
        if response.status_code != (200 if in_flight else 202):
            raise FixtureError(f"OBSERVATION_HTTP_{response.status_code}")
        value = response.json()
        if not in_flight:
            job_id = value.get("id")
            if not isinstance(job_id, str) or not re.fullmatch(ULID, job_id):
                raise FixtureError("OBSERVATION_JOB_ID_INVALID")
            self.pending = job_id
            progress["started"] += 1
        elif value.get("status") in {"SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME", "CANCELLED_SAFE"}:
            status = value["status"]
            progress[status] += 1
            self.pending = None
            self.next_target = (self.next_target + 1) % len(self.targets)
            result = value.get("result")
            if status == "SUCCEEDED":
                if isinstance(result, dict) and result.get("status") == "REACHABLE":
                    return target
                progress["NOT_REACHABLE"] += 1
        return None

    def phase(self, seconds, interval):
        start = time.monotonic()
        end = start + seconds
        latency = {name: Counter() for name in ENDPOINTS}
        errors = Counter()
        jobs = Counter()
        observed = set()
        canaries = 0
        with ThreadPoolExecutor(max_workers=READ_CONCURRENCY) as pool:
            while time.monotonic() < end:
                iteration = time.monotonic()
                target = self.targets[self.next_target]
                reads = [pool.submit(self.read, name, target) for name in ENDPOINTS]
                observed_target = self.probe_step(jobs)
                if observed_target is not None:
                    observed.add(observed_target)
                for read in reads:
                    name, ms, status, leaked = read.result()
                    canaries += leaked
                    if status == "200":
                        latency[name][ms] += 1
                    else:
                        errors[status] += 1
                time.sleep(max(0, min(iteration + interval, end) - time.monotonic()))
        return {
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "latency_ms": {name: summary(samples) for name, samples in latency.items()},
            "unexpected_responses": dict(errors), "response_canaries": canaries,
            "jobs": dict(jobs), "targets_verified": len(observed),
        }

    def burst_and_quota(self):
        # Drain the rolling quota from the soak with no calls from this dedicated fixture account.
        time.sleep(61)
        ready = Barrier(100, timeout=30)
        endpoints = tuple(ENDPOINTS)

        def simultaneous_read(index):
            ready.wait()
            return self.read(endpoints[index % len(endpoints)], self.targets[index % len(self.targets)])

        with ThreadPoolExecutor(max_workers=100) as pool:
            burst = list(pool.map(simultaneous_read, range(100)))
        statuses = Counter(status for _, _, status, _ in burst)
        expected = statuses == {"200": 100} and not any(leaked for _, _, _, leaked in burst)
        if not expected:
            return {"passed": False, "burst_statuses": dict(statuses)}
        quota = [self.client.get(ENDPOINTS["session"]) for _ in range(21)]
        refusal = quota[-1]
        passed = (
            all(reply.status_code == 200 for reply in quota[:-1])
            and refusal.status_code == 429
            and refusal.headers.get("retry-after") == "60"
            and refusal.json().get("code") == "API_RATE_LIMIT"
            and not any(secret in reply.text for reply in quota for secret in self.canaries)
        )
        return {
            "passed": passed, "burst_statuses": dict(statuses),
            "burst_latency_ms": {name: summary(Counter(ms for route, ms, _, _ in burst if name == route))
                                 for name in endpoints},
            "quota_statuses": dict(Counter(str(reply.status_code) for reply in quota)),
        }


def preflight(client, inventory_file):
    targets = inventory_file.read_text(encoding="utf-8").split()
    if len(set(targets)) != HOSTS or len(targets) != HOSTS or any(not re.fullmatch(ULID, target) for target in targets):
        raise FixtureError("EXACTLY_25_UNIQUE_FIXTURE_ULIDS_REQUIRED")
    response = client.get("/api/v1/resources?limit=100")
    if response.status_code != 200:
        raise FixtureError(f"INVENTORY_PREFLIGHT_HTTP_{response.status_code}")
    inventory = response.json()
    items = inventory["items"]
    if (inventory["next_after"] is not None or {item["id"] for item in items} != set(targets)
            or any(not item["enabled"] for item in items)):
        raise FixtureError("CONTROLLER_INVENTORY_DOES_NOT_MATCH_FIXTURE")
    services = sum(len(((item["observation"]["last_success"] or {}).get("docker") or {}).get("containers") or [])
                   for item in items)
    if services != HOSTS * SERVICES_PER_HOST:
        raise FixtureError("EXACTLY_200_ALREADY_OBSERVED_SERVICES_REQUIRED")
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-fixture", action="store_true", required=True)
    parser.add_argument("--origin", required=True, help="Loopback HTTPS origin of the installed fixture")
    parser.add_argument("--ca", required=True, type=Path, help="CA for the fixture HTTPS endpoint")
    parser.add_argument("--targets", required=True, type=Path, help="Fixture file with 25 unique target IDs")
    parser.add_argument("--username", required=True, help="Dedicated fixture account with inventory, audit and probe access")
    parser.add_argument("--warmup", type=int, default=WARMUP_SECONDS)
    parser.add_argument("--seconds", type=int, default=SOAK_SECONDS)
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--check-quota", action="store_true", help="Run the 100-read burst and API user quota check")
    args = parser.parse_args()
    try:
        parsed = urlsplit(args.origin)
        host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
        origin = "https://" + host + (f":{parsed.port}" if parsed.port else "")
        if args.origin != origin:
            raise ValueError
    except ValueError:
        parser.error("Specify a loopback HTTPS origin without credentials or a path.")
    if not 0 <= args.warmup <= WARMUP_SECONDS or not 1 <= args.seconds <= SOAK_SECONDS or not 4 <= args.interval <= 60:
        parser.error("Use between 0 and 1,800 warmup seconds, 1–28,800 soak seconds and a 4–60 second interval.")
    report = {
        "profile": "installed_controller_https_ssh", "release_acceptance": False, "status": "WORKLOAD_FAILED",
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "warmup_seconds": args.warmup,
        "soak_seconds": args.seconds, "interval_seconds": args.interval,
        "fixture_hosts": HOSTS, "fixture_services": HOSTS * SERVICES_PER_HOST,
        "read_concurrency": READ_CONCURRENCY, "environment": environment(Path.cwd()),
    }
    password = getpass.getpass("Fixture password: ")
    try:
        with httpx.Client(base_url=args.origin, verify=ssl.create_default_context(cafile=args.ca), trust_env=False,
                          headers={"Origin": args.origin}, timeout=15, limits=httpx.Limits(max_connections=100)) as client:
            login = client.post("/api/v1/auth/login", json={"username": args.username, "password": password})
            if login.status_code != 200:
                raise FixtureError(f"LOGIN_HTTP_{login.status_code}")
            targets = preflight(client, args.targets)
            workload = Workload(client, targets, password, login.json()["csrf_token"])
            report["warmup"] = workload.phase(args.warmup, args.interval)
            report["measured"] = measured = workload.phase(args.seconds, args.interval)
            report["pending_read_only_probe"] = workload.pending is not None
            if args.check_quota:
                report["burst_and_quota"] = workload.burst_and_quota()
            phases_clean = all(
                not report[phase]["unexpected_responses"] and not report[phase]["response_canaries"]
                and not set(report[phase]["jobs"]).difference({"started", "SUCCEEDED"})
                for phase in ("warmup", "measured")
            )
            full = args.seconds == SOAK_SECONDS
            enough_jobs = measured["targets_verified"] == HOSTS if full else measured["jobs"].get("SUCCEEDED", 0) > 0
            fast = all(0 < (endpoint["p95"] or 0) <= READ_P95_MS for endpoint in measured["latency_ms"].values())
            if phases_clean and fast and enough_jobs and report.get("burst_and_quota", {}).get("passed", True):
                report["status"] = "WORKLOAD_PASSED"
    except FixtureError as error:
        report["failure"] = str(error)
    except (BrokenBarrierError, OSError, httpx.HTTPError, KeyError, TypeError, ValueError) as error:
        report["failure"] = type(error).__name__
    print(json.dumps({**report, "finished_at_utc": datetime.now(timezone.utc).isoformat()}, sort_keys=True))
    return 0 if report["status"] == "WORKLOAD_PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
