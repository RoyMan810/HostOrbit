"""Run the local defensive security regressions against disposable fixtures."""

from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sqlite3
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    "tests_app": ("test_auth_api.py", "test_http_boundary.py", "test_permissions.py", "test_queue_api.py"),
    "tests_runtime": ("test_credentials.py", "test_worker_broker.py"),
}


def main():
    started = datetime.now(timezone.utc)
    observations = []
    for directory, modules in SUITES.items():
        for module in modules:
            suite = unittest.TestLoader().discover(str(ROOT / directory), pattern=module)
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
            observations.append({
                "suite": f"{directory}/{module}",
                "run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "passed": result.testsRun > 0 and result.wasSuccessful() and not result.skipped,
            })
    passed = all(suite["passed"] for suite in observations)
    print(json.dumps({
        "status": "PASSED" if passed else "FAILED",
        "scope": "LOCAL_DEFENSIVE_REGRESSIONS",
        "release_acceptance": False,
        "started_at_utc": started.isoformat(),
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "suites": observations,
    }, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
