"""A fixture that signals receipt of SIGTERM and waits to exit."""

from pathlib import Path
import signal
import time


root = Path("/fixture")


def stop(_signal, _frame):
    (root / "stop-received").touch()
    while not (root / "release-stop").exists():
        time.sleep(0.02)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
(root / "ready").touch()
while True:
    time.sleep(1)
