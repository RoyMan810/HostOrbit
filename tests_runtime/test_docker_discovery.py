from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from hostorbit.errors import Denied
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.ssh import parse_probe


TARGET = "a" * 64
FOREIGN = "b" * 64
SCOPE = [{"id": TARGET, "project": "fixture", "service": "web"}]
ROW = {**SCOPE[0], "state": "RUNNING"}
SUMMARY = {"status": "OBSERVED", "containers": [ROW]}
BINDING = {"address": "127.0.0.1", "host_port": 49152, "container_port": 8080, "protocol": "tcp"}
IPV6_BINDING = {"address": "::", "host_port": 49152, "container_port": 8080, "protocol": "udp"}
DAEMON_PORTS = [
    {"IP": "127.0.0.1", "PublicPort": 49152, "PrivatePort": 8080, "Type": "tcp"},
    {"IP": "0:0:0:0:0:0:0:0", "PublicPort": 49152, "PrivatePort": 8080, "Type": "udp"},
    {"PrivatePort": 8443, "Type": "tcp"},
    {"IP": "::", "PrivatePort": 8080, "Type": "tcp"},
]
HELPER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "remote/typed-helper"))


class DockerPayloadTests(unittest.TestCase):
    def parse(self, docker, version=3):
        value = {"v": version, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
                 "docker": docker}
        return parse_probe(canonical(value), version, now=1000)

    def test_v3_accepts_only_the_bounded_typed_summary(self):
        self.assertEqual(self.parse(SUMMARY)["docker"], SUMMARY)
        for payload in ({"status": "OBSERVED", "containers": []},
                        {"status": "NOT_CONFIGURED", "containers": [ROW]},
                        {"status": "OBSERVED", "containers": [ROW, ROW]},
                        {"status": "OBSERVED", "containers": [{**ROW, "env": ["canary"]}]},
                        {"status": "OBSERVED", "containers": [{**ROW, "state": "HEALTHY"}]},
                        {"status": "OBSERVED", "containers": [{**ROW, "project": "../private"}]}):
            with self.subTest(payload=payload), self.assertRaises(Denied):
                self.parse(payload)

    def test_v4_requires_typed_and_bounded_bindings(self):
        def summary(ports, *, state="RUNNING"):
            return {"status": "OBSERVED", "containers": [{**ROW, "state": state, "published_ports": ports}]}

        for ports in (None, [], [BINDING, IPV6_BINDING]):
            with self.subTest(ports=ports):
                payload = summary(ports)
                self.assertEqual(self.parse(payload, version=4)["docker"], payload)
                with self.assertRaises(Denied):
                    self.parse(payload, version=3)
        for payload in (
            SUMMARY,
            summary([BINDING], state="NOT_FOUND"),
            summary([], state="UNKNOWN"),
            summary([BINDING, BINDING]),
            summary([{**BINDING, "host_port": port} for port in range(1, 10)]),
            summary([{**BINDING, "address": "fe80::1%eth0"}]),
            summary([{**BINDING, "address": "0:0:0:0:0:0:0:0"}]),
            summary([{**BINDING, "host_port": True}]),
            summary([{**BINDING, "container_port": 65536}]),
            summary([{**BINDING, "protocol": "icmp"}]),
            summary([{**BINDING, "label": "secret"}]),
        ):
            with self.subTest(payload=payload), self.assertRaises(Denied):
                self.parse(payload, version=4)

    def test_v5_requires_a_mount_status_and_keeps_older_payloads_strict(self):
        for status in ("NONE", "PRESENT", "UNKNOWN"):
            payload = {"status": "OBSERVED", "containers": [
                {**ROW, "published_ports": [], "mount_status": status},
            ]}
            self.assertEqual(self.parse(payload, version=5)["docker"], payload)
            with self.assertRaises(Denied):
                self.parse(payload, version=4)
        for row in ({**ROW, "published_ports": []},
                    {**ROW, "published_ports": [], "mount_status": []},
                    {**ROW, "state": "NOT_FOUND", "published_ports": None, "mount_status": "NONE"}):
            with self.subTest(row=row), self.assertRaises(Denied):
                self.parse({"status": "OBSERVED", "containers": [row]}, version=5)

    def test_v6_requires_typed_network_status_without_changing_v5(self):
        row = {**ROW, "published_ports": [], "mount_status": "NONE"}
        for status in ("ISOLATED", "OTHER", "UNKNOWN"):
            summary = {"status": "OBSERVED", "containers": [{**row, "network_status": status}]}
            self.assertEqual(self.parse(summary, version=6)["docker"], summary)
            with self.assertRaises(Denied):
                self.parse(summary, version=5)
        for invalid in (row, {**row, "network_status": "bridge"},
                        {**row, "state": "CREATED", "mount_status": "UNKNOWN", "network_status": "ISOLATED"}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                self.parse({"status": "OBSERVED", "containers": [invalid]}, version=6)

    def test_protected_registry_requires_full_unique_ids_and_exact_fields(self):
        parse = HELPER["parse_docker_scope"]
        self.assertEqual(parse(canonical({"v": 1, "containers": SCOPE})), SCOPE)
        for scope in ([{**SCOPE[0], "id": TARGET[:12]}], SCOPE * 2,
                      [{**SCOPE[0], "service": "/etc/passwd"}],
                      [{**SCOPE[0], "mount": "secret"}],
                      [{"id": format(i, "064x"), "project": "p", "service": "s"} for i in range(9)]):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                parse(canonical({"v": 1, "containers": scope}))
        with self.assertRaises(ValueError):
            parse(b'{"v":1,"v":1,"containers":[]}')


class DockerTransportTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.response = [{"Id": TARGET, "State": "running",
                          "Labels": {"com.docker.compose.project": "fixture",
                                     "com.docker.compose.service": "web", "secret": "label-canary"},
                          "Command": "command-canary", "Mounts": [{"Source": "/private/path"}]}]
        self.inspect = {"Id": TARGET, "Config": {"Labels": self.response[0]["Labels"], "Env": ["secret-canary"]},
                        "State": {"Status": "running"}, "HostConfig": {}, "Mounts": []}
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append(self.path)
                value = fixture.inspect if self.path == f"/v1.44/containers/{TARGET}/json" else fixture.response
                if value is None:
                    self.send_error(404)
                    return
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        # The local sandbox denies AF_UNIX creation. CI exercises the real daemon socket.
        self.enterContext(patch.dict(HELPER["list_docker"].__globals__, {
            "DockerConnection": lambda _: HTTPConnection("127.0.0.1", server.server_port, timeout=2),
        }))

    def observe(self, **options):
        return HELPER["list_docker"](Path("/unused.sock"), SCOPE, **options)

    def test_reads_only_approved_ids_and_projects_fixed_fields(self):
        self.assertEqual(self.observe(), [ROW])
        self.assertEqual(len(self.requests), 1)
        route = urlsplit(self.requests[0])
        self.assertEqual(route.path, "/v1.44/containers/json")
        query = parse_qs(route.query)
        self.assertEqual(query["all"], ["1"])
        self.assertEqual(json.loads(query["filters"][0]), {"id": [TARGET]})

    def test_foreign_or_duplicate_daemon_results_fail_closed(self):
        first = self.response[0]
        for response in ([first, {**first, "Id": FOREIGN}], [first, first]):
            self.response = response
            with self.assertRaises(ValueError):
                self.observe()

    def test_missing_id_and_changed_compose_identity_are_distinct(self):
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong-project"
        self.assertEqual(self.observe(), [{**SCOPE[0], "state": "UNKNOWN"}])
        self.response = []
        self.assertEqual(self.observe(), [{**SCOPE[0], "state": "NOT_FOUND"}])

    def test_published_ports_are_filtered_and_normalized_in_one_scoped_request(self):
        self.response[0]["Ports"] = [*DAEMON_PORTS, DAEMON_PORTS[0]]
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "published_ports": [BINDING, IPV6_BINDING]},
        ])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.observe(), [ROW])

    def test_unpublished_ports_and_incomplete_ports_are_distinct(self):
        for ports, expected in (
            (DAEMON_PORTS[2:], []),
            (None, None),
            ([{"PrivatePort": True, "Type": "tcp"}], None),
            ([{**DAEMON_PORTS[3], "IP": "invalid"}], None),
            ([DAEMON_PORTS[0], {**DAEMON_PORTS[1], "IP": "invalid"}], None),
            ([{**DAEMON_PORTS[0], "PublicPort": port} for port in range(1, 10)], None),
        ):
            with self.subTest(ports=ports):
                self.response[0]["Ports"] = ports
                self.assertEqual(self.observe(include_ports=True), [{**ROW, "published_ports": expected}])

    def test_ports_are_hidden_when_compose_identity_is_unverified(self):
        self.response[0]["Ports"] = DAEMON_PORTS
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong-project"
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "state": "UNKNOWN", "published_ports": None},
        ])
        self.response = []
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "state": "NOT_FOUND", "published_ports": None},
        ])


    def test_inspects_only_the_matched_running_container_and_projects_mount_status(self):
        for mounts, config, expected in (
            ([], {}, "NONE"),
            ([{"Type": "volume", "Source": "/private/path"}], {}, "PRESENT"),
            ([], {"Binds": ["/private/path:/data"]}, "PRESENT"),
            ([], {"Tmpfs": {"/data": "size=1m"}}, "PRESENT"),
            (None, {}, "UNKNOWN"),
            ([], {"Binds": ""}, "UNKNOWN"),
        ):
            with self.subTest(mounts=mounts, config=config):
                self.requests.clear()
                self.inspect.update(Mounts=mounts, HostConfig=config)
                self.assertEqual(self.observe(include_ports=True, include_mounts=True), [
                    {**ROW, "published_ports": None, "mount_status": expected},
                ])
                self.assertEqual(len(self.requests), 2)
                self.assertEqual(self.requests[1], f"/v1.44/containers/{TARGET}/json")
        self.inspect = None
        self.assertEqual(self.observe(include_ports=True, include_mounts=True)[0]["mount_status"], "UNKNOWN")
        self.requests.clear()
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong"
        self.assertEqual(self.observe(include_ports=True, include_mounts=True)[0]["mount_status"], "UNKNOWN")
        self.assertEqual(len(self.requests), 1)

    def test_inspects_network_without_publishing_network_details_or_requesting_a_second_inspect(self):
        for mode, networks, expected in (
            ("none", {"none": {}}, "ISOLATED"),
            ("bridge", {"private-network": {"IPAddress": "192.0.2.10"}}, "OTHER"),
            ("host", {"host": {}}, "OTHER"),
            ("container:peer", {}, "OTHER"),
            ("none", {"none": {}, "private-network": {}}, "OTHER"),
            ("none", {}, "UNKNOWN"),
            ("none", None, "UNKNOWN"),
        ):
            with self.subTest(mode=mode, networks=networks):
                self.requests.clear()
                self.inspect["HostConfig"]["NetworkMode"] = mode
                self.inspect["NetworkSettings"] = {"Networks": networks}
                self.assertEqual(self.observe(include_ports=True, include_mounts=True, include_network=True), [
                    {**ROW, "published_ports": None, "mount_status": "NONE", "network_status": expected},
                ])
                self.assertEqual(len(self.requests), 2)
        self.inspect["Id"] = FOREIGN
        self.assertEqual(self.observe(include_ports=True, include_mounts=True, include_network=True)[0]["network_status"],
                         "UNKNOWN")
