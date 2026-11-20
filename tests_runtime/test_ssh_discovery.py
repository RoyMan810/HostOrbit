import asyncio
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import asyncssh

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.protocol import canonical
from vpn_orbit.runtime.ssh import exchange, exchange_restart, parse_probe


BOOT = '12345678-1234-1234-1234-123456789abc'
SOFTWARE = {'docker': 'PRESENT', 'nginx': 'NOT_DETECTED'}


class DiscoveryPayloadTests(unittest.TestCase):
    def parse(self, version, **extra):
        return parse_probe(canonical({'v': version, 'uid': 0, 'boot_id': BOOT, 'observed_at': 1000, **extra}),
                           version, now=1000)

    def test_legacy_probe_remains_compatible(self):
        self.assertEqual(self.parse(1), {'status': 'REACHABLE', 'source': 'restricted_helper',
                                         'observed_at': 1000, 'boot_id': BOOT})

    def test_v2_accepts_only_fixed_component_states(self):
        self.assertEqual(self.parse(2, software=SOFTWARE)['software'], SOFTWARE)
        for extra in ({}, {'software': {'docker': '/private/key', 'nginx': 'UNKNOWN'}},
                      {'software': {**SOFTWARE, 'shell': 'PRESENT'}}, {'software': {'docker': 'PRESENT'}},
                      {'software': {**SOFTWARE, 'nginx': []}}, {'software': SOFTWARE, 'raw': 'canary'}):
            with self.subTest(extra=extra), self.assertRaises(Denied):
                self.parse(2, **extra)
        with self.assertRaises(Denied):
            self.parse(1, software=SOFTWARE)

    def test_remote_helper_only_checks_fixed_file_metadata(self):
        helper = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'remote/typed-helper'))
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'docker'
            executable.touch(mode=0o700)
            # Container builds may remap system file owners. Model the root-owned installation.
            metadata = SimpleNamespace(st_mode=executable.stat().st_mode, st_uid=0)
            with patch.object(Path, 'stat', return_value=metadata):
                self.assertEqual(helper['tool_status'](executable), 'PRESENT')
                metadata.st_uid = 65534
                self.assertEqual(helper['tool_status'](executable), 'UNKNOWN')
            self.assertEqual(helper['tool_status'](Path(directory) / 'missing'), 'NOT_DETECTED')
            self.assertEqual(helper['tool_status'](directory), 'UNKNOWN')


class ProbeNegotiationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.reply = lambda command: (0, b'probe')
        key = asyncssh.generate_private_key('ssh-ed25519')
        self.client_key = asyncssh.generate_private_key('ssh-ed25519')
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.known_hosts = directory / 'known_hosts'
        self.known_hosts.write_bytes(b'vpn-orbit-discovery ' + key.export_public_key())

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return False

        async def command(process):
            self.requests.append((process.command, await process.stdin.read()))
            status, output = self.reply(process.command)
            process.stdout.write(output)
            process.exit(status)

        server = await asyncssh.listen('127.0.0.1', 0, server_factory=Server,
                                      server_host_keys=[key], process_factory=command, encoding=None)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        self.target = SimpleNamespace(id='discovery', value={'ip': '127.0.0.1', 'port': server.get_port()})

    async def probe(self):
        return await asyncio.wait_for(exchange(self.target, self.client_key, self.known_hosts), 5)

    async def test_v8_uses_one_fixed_request(self):
        self.assertEqual(await self.probe(), (8, b'probe'))
        self.assertEqual(self.requests, [('vpn-orbit.v8.probe', b'{"operation":"probe","version":8}\n')])

    async def test_silent_unsupported_probe_versions_fall_back(self):
        for version in (7, 6, 5, 4, 3, 2, 1):
            with self.subTest(version=version):
                self.requests.clear()
                self.reply = lambda command: (0, b'legacy') if command == f'vpn-orbit.v{version}.probe' else (65, b'')
                self.assertEqual(await self.probe(), (version, b'legacy'))
                self.assertEqual([r[0] for r in self.requests],
                                 [f'vpn-orbit.v{step}.probe' for step in range(8, version - 1, -1)])

    async def test_failed_or_noisy_probe_does_not_fall_back(self):
        for status, data in ((65, b'canary'), (1, b'')):
            with self.subTest(status=status):
                self.requests.clear()
                self.reply = lambda command: (status, data)
                with self.assertRaisesRegex(Denied, 'SSH_REMOTE_PROBE_FAILED'):
                    await self.probe()
                self.assertEqual(len(self.requests), 1)


    async def test_restart_is_one_fixed_command_with_a_typed_reply(self):
        request = {"operation_id": "0" * 26, "container_id": "a" * 64, "boot_id": BOOT,
                   "started_at": "2026-11-18T01:02:03.123456789Z"}
        result = {"outcome": "SUCCEEDED", "code": "DOCKER_RESTART_VERIFIED"}
        self.reply = lambda _: (0, canonical(result))
        output = await exchange_restart(self.target, self.client_key, self.known_hosts, request)
        self.assertEqual(output, result)
        self.assertEqual(self.requests, [("vpn-orbit.v1.docker-restart", canonical(request) + b"\n")])
        self.requests.clear()
        self.reply = lambda _: (70, canonical(result))
        with self.assertRaisesRegex(Denied, "SSH_RESTART_REPLY_INVALID"):
            await exchange_restart(self.target, self.client_key, self.known_hosts, request)
        self.assertEqual(len(self.requests), 1)
