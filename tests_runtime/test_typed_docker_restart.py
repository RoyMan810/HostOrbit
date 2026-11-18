from contextlib import nullcontext
import json
import os
from pathlib import Path
import runpy
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_docker_discovery import HELPER


RESTART = runpy.run_path(str(Path(__file__).resolve().parents[1] / "remote/docker-restart"))
BOOT = "12345678-1234-1234-1234-123456789abc"
START = "2026-11-17T00:00:00.123456789Z"
AFTER = "2026-11-17T00:00:02.123456789Z"
TARGET = {"id": "a" * 64, "project": "fixture", "service": "web"}
REQUEST = {"operation_id": "A" * 26, "container_id": TARGET["id"], "boot_id": BOOT, "started_at": START}


class TypedRestartTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        boot = self.root / "boot"
        boot.write_text(BOOT)
        self.connection = Mock()
        self.connection.getresponse.return_value = nullcontext(SimpleNamespace(status=204))
        self.inspect = Mock(side_effect=[{"State": {"StartedAt": at}, "HostConfig": {}} for at in (START, AFTER)])
        self.helper = {**HELPER, "read_docker_scope": Mock(return_value=[TARGET]), "inspect_container": self.inspect,
                       "mount_status": Mock(return_value="NONE"), "network_status": Mock(return_value="ISOLATED"),
                       "dependency_status": Mock(return_value="ISOLATED"), "protected_directory": Mock(return_value=True),
                       "DockerConnection": Mock(return_value=self.connection)}
        docker_socket = Mock()
        docker_socket.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        self.arguments = {"journal": self.root, "boot_id": boot, "socket_path": docker_socket,
                          "discovery": self.root / "discovery", "policy": self.root / "policy"}

    def run_request(self, request=REQUEST):
        fstat = os.fstat
        def root_owned(fd):
            value = fstat(fd)
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0)
        with patch.object(os, "fstat", side_effect=root_owned):
            return RESTART["restart_once"](request, self.helper, **self.arguments)

    def test_exact_restart_and_verified_retry_do_not_send_twice(self):
        self.assertEqual(RESTART["parse"](json.dumps(REQUEST).encode(), HELPER), REQUEST)
        self.assertEqual(self.run_request(), ("SUCCEEDED", "DOCKER_RESTART_VERIFIED"))
        self.assertEqual(self.run_request(), ("SUCCEEDED", "RESTART_ALREADY_VERIFIED"))
        self.connection.request.assert_called_once_with("POST", f"/v1.44/containers/{TARGET['id']}/restart?t=2")
        with self.assertRaisesRegex(RESTART["Refused"], "RESTART_REQUEST_CONFLICT"):
            self.run_request({**REQUEST, "started_at": AFTER})

    def test_unknown_outcome_blocks_replay_and_new_operation(self):
        self.connection.getresponse.side_effect = TimeoutError
        self.assertEqual(self.run_request(), ("UNKNOWN_OUTCOME", "DOCKER_EFFECT_UNVERIFIED"))
        self.assertEqual(self.run_request(), ("UNKNOWN_OUTCOME", "RESTART_OUTCOME_UNVERIFIED"))
        with self.assertRaisesRegex(RESTART["Refused"], "RESTART_INCIDENT_OPEN"):
            self.run_request({**REQUEST, "operation_id": "B" * 26})
        self.connection.request.assert_called_once()

    def test_docker_ack_without_a_new_start_is_unknown(self):
        self.inspect.side_effect = [{"State": {"StartedAt": START}, "HostConfig": {}}] * 2
        self.assertEqual(self.run_request(), ("UNKNOWN_OUTCOME", "DOCKER_EFFECT_UNVERIFIED"))

    def test_stale_baseline_and_nonisolated_container_are_denied_before_dispatch(self):
        with self.assertRaisesRegex(RESTART["Refused"], "STALE_BASELINE"):
            self.run_request({**REQUEST, "started_at": AFTER})
        self.inspect.side_effect = None
        self.inspect.return_value = {"State": {"StartedAt": START}, "HostConfig": {}}
        self.helper["dependency_status"].return_value = "OTHER"
        with self.assertRaisesRegex(RESTART["Refused"], "CONTAINER_NOT_ISOLATED"):
            self.run_request()
        self.connection.request.assert_not_called()
        self.assertEqual(sorted(self.root.iterdir()), [self.arguments["boot_id"]])
