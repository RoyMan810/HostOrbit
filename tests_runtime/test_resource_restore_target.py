import errno
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
from socketserver import UnixStreamServer
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from hostorbit.errors import Denied
from hostorbit.runtime.resource_restore_target import check_restore_target


class RestoreTargetTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.docker_root = root / "docker"
        self.socket = root / "docker.sock"
        self.name = "orbit-restore-fixture"
        self.data = self.docker_root / "volumes" / self.name / "_data"
        self.data.mkdir(parents=True)
        self.created = "2026-11-10T09:30:00Z"
        self.volume = {"Name": self.name, "Driver": "local", "Scope": "local", "Options": None,
                       "Mountpoint": str(self.data), "CreatedAt": self.created}
        self.attached = False
        self.requests = []

    def reply(self, socket_path, owner, endpoint):
        self.assertEqual((socket_path, owner), (self.socket, os.geteuid()))
        self.requests.append(endpoint)
        if endpoint == f"/volumes/{self.name}":
            return self.volume
        self.assertEqual(urlsplit(endpoint).path, "/volumes")
        return {"Volumes": [] if self.attached else [self.volume], "Warnings": None}

    def test_reads_docker_api_over_a_local_unix_socket(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if not self.path.startswith("/v1.44/"):
                    self.send_error(404)
                    return
                value = fixture.reply(fixture.socket, os.geteuid(), self.path.removeprefix("/v1.44"))
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        try:
            server = self.enterContext(UnixStreamServer(str(self.socket), Handler))
        except PermissionError as error:
            if error.errno in (errno.EPERM, errno.EACCES) and os.environ.get("GITHUB_ACTIONS") != "true":
                self.skipTest("Unix socket creation blocked by the local executor")
            raise
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        result = check_restore_target(self.name, expected_created_at=self.created, required_bytes=1,
                                      required_inodes=1, docker_root=self.docker_root,
                                      socket_path=self.socket, owner=os.geteuid())
        self.assertEqual(result["status"], "EMPTY_TARGET_CHECKED")
        self.assertEqual(len(self.requests), 2)

    def check(self, *, required_bytes=1, required_inodes=1, expected_fingerprint=None, reply=None):
        with patch("hostorbit.runtime.resource_restore_target._get", side_effect=reply or self.reply):
            return check_restore_target(self.name, expected_created_at=self.created, required_bytes=required_bytes,
                                        required_inodes=required_inodes, docker_root=self.docker_root,
                                        socket_path=self.socket, owner=os.geteuid(),
                                        expected_fingerprint=expected_fingerprint)

    def test_checks_empty_unreferenced_volume_without_writing(self):
        result = self.check()
        self.assertEqual(result["status"], "EMPTY_TARGET_CHECKED")
        self.assertEqual(result["target"], self.name)
        self.assertEqual(result["restore_eligibility"], "NOT_EVALUATED")
        self.assertEqual(list(self.data.iterdir()), [])
        query = parse_qs(urlsplit(self.requests[-1]).query)
        self.assertEqual(json.loads(query["filters"][0]), {"dangling": ["true"], "name": [self.name]})

    def test_rechecks_the_same_empty_directory_and_capacity_budget(self):
        initial = self.check()["target_fingerprint"]
        self.assertRegex(initial, r"^[0-9a-f]{64}$")
        self.assertEqual(self.check(expected_fingerprint=initial)["target_fingerprint"], initial)
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_CHANGED"):
            self.check(expected_fingerprint=initial, required_bytes=2)

    def test_rejects_recreated_directory_with_identical_docker_metadata(self):
        initial = self.check()["target_fingerprint"]
        self.data.rename(self.data.with_name("_old"))
        self.data.mkdir()
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_CHANGED"):
            self.check(expected_fingerprint=initial)

    def test_detects_replacement_between_directory_and_docker_reference_checks(self):
        def replace_after_first_check(socket_path, owner, endpoint):
            if urlsplit(endpoint).path == "/volumes":
                self.data.rename(self.data.with_name("_old"))
                self.data.mkdir()
            return self.reply(socket_path, owner, endpoint)

        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_CHANGED"):
            self.check(reply=replace_after_first_check)

    def test_reserved_volume_requires_only_its_created_helper(self):
        reservation, container = "a" * 32, "b" * 64
        self.volume["Labels"] = {"org.hostorbit.resource-restore": reservation}
        references = [{"Id": container, "State": "created"}]

        def reply(socket_path, owner, endpoint, reply_type=dict):
            if urlsplit(endpoint).path == "/containers/json":
                self.assertIs(reply_type, list)
                query = parse_qs(urlsplit(endpoint).query)
                self.assertEqual(query["all"], ["1"])
                self.assertEqual(json.loads(query["filters"][0]), {"volume": [self.name]})
                return references
            return self.reply(socket_path, owner, endpoint)

        kwargs = {"expected_created_at": self.created, "required_bytes": 1, "required_inodes": 1,
                  "docker_root": self.docker_root, "socket_path": self.socket, "owner": os.geteuid(),
                  "reservation": reservation}
        with patch("hostorbit.runtime.resource_restore_target._get", side_effect=reply):
            baseline = check_restore_target(self.name, **kwargs)
            kwargs.update(expected_container=container, expected_fingerprint=baseline["target_fingerprint"])
            self.assertEqual(check_restore_target(self.name, **kwargs), baseline)
            references.append({"Id": "c" * 64, "State": "exited"})
            with self.assertRaisesRegex(Denied, "RESTORE_TARGET_REFERENCED"):
                check_restore_target(self.name, **kwargs)

    def test_refuses_occupied_and_referenced_targets(self):
        marker = self.data / ".owner-data"
        marker.write_text("preserve")
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_OCCUPIED"):
            self.check()
        self.assertEqual(marker.read_text(), "preserve")
        marker.unlink()
        self.attached = True
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_REFERENCED"):
            self.check()

    def test_refuses_wrong_identity_mount_options_and_symlink(self):
        original = self.volume.copy()
        for change in ({"CreatedAt": "2026-11-10T09:40:00Z"}, {"Driver": "external"},
                       {"Options": {"device": "/other"}}, {"Mountpoint": str(self.data.parent)}):
            self.volume = {**original, **change}
            with self.subTest(change=change), self.assertRaisesRegex(Denied, "RESTORE_TARGET_UNTRUSTED"):
                self.check()
        self.volume = original
        self.data.rmdir()
        self.data.symlink_to(self.docker_root, target_is_directory=True)
        with self.assertRaisesRegex(Denied, "RESTORE_TARGET_UNTRUSTED"):
            self.check()

    def test_refuses_insufficient_bytes_or_inodes(self):
        for values in ({"required_bytes": 2**63 - 1}, {"required_inodes": 2**63 - 1}):
            with self.subTest(values=values), self.assertRaisesRegex(Denied, "RESTORE_TARGET_CAPACITY"):
                self.check(**values)
