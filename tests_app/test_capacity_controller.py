from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from hostorbit.auth import COOKIE
from tools.capacity_controller import FixtureError, Workload, preflight


TARGETS = [f"01JCYQZ4T9V8MNVYEH3D2M7Q{index:02d}" for index in range(25)]
JOB = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"


class CapacityControllerTests(unittest.TestCase):
    def test_preflight_requires_exactly_the_approved_fixture_and_observed_services(self):
        items = [{
            "id": target, "enabled": True,
            "observation": {"last_success": {"docker": {"containers": [{}] * 8}}},
        } for target in TARGETS]

        def inventory(request):
            self.assertEqual(request.url.path, "/api/v1/resources")
            return httpx.Response(200, json={"items": items, "next_after": None})

        with (tempfile.TemporaryDirectory() as directory,
              httpx.Client(base_url="https://127.0.0.1", transport=httpx.MockTransport(inventory)) as client):
            path = Path(directory) / "targets"
            path.write_text("\n".join(TARGETS), encoding="utf-8")
            self.assertEqual(preflight(client, path), TARGETS)
            items[0]["observation"]["last_success"] = None
            with self.assertRaisesRegex(FixtureError, "200_ALREADY_OBSERVED_SERVICES_REQUIRED"):
                preflight(client, path)
            items[0]["enabled"] = False
            with self.assertRaisesRegex(FixtureError, "INVENTORY_DOES_NOT_MATCH"):
                preflight(client, path)

    def test_observations_are_confirmed_and_only_one_probe_is_outstanding(self):
        requests = []

        def route(request):
            requests.append((request.method, request.url.path))
            if request.method == "POST":
                self.assertEqual(request.headers["x-csrf-token"], "csrf")
                self.assertTrue(request.headers["idempotency-key"])
                self.assertEqual(json.loads(request.content), {})
                return httpx.Response(202, json={"id": JOB})
            if len(requests) == 2:
                return httpx.Response(200, json={"status": "EXECUTING"})
            return httpx.Response(200, json={"status": "SUCCEEDED", "result": {"status": "REACHABLE"}})

        with httpx.Client(base_url="https://127.0.0.1", transport=httpx.MockTransport(route),
                          cookies={COOKIE: "session-cookie"}) as client:
            workload = Workload(client, TARGETS, "fixture-password", "csrf")
            jobs = Counter()
            self.assertIsNone(workload.probe_step(jobs))
            self.assertIsNone(workload.probe_step(jobs))
            self.assertEqual(workload.probe_step(jobs), TARGETS[0])
            self.assertIsNone(workload.probe_step(jobs))
            self.assertEqual(jobs, {"started": 2, "SUCCEEDED": 1})
            self.assertEqual(requests, [
                ("POST", f"/api/v1/resources/{TARGETS[0]}/observations"),
                ("GET", f"/api/v1/jobs/{JOB}"),
                ("GET", f"/api/v1/jobs/{JOB}"),
                ("POST", f"/api/v1/resources/{TARGETS[1]}/observations"),
            ])
