from contextlib import contextmanager
from dataclasses import replace
import hashlib
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import time
import unittest

from nacl.signing import SigningKey

from stage0.admission import ControllerMode, Denied, FixtureObservation, GateState, HostGate, Outcome, UpdateKind
from stage0.recovery import RecoveryTarget, Rejected, activation_attestation


TOPOLOGY = {
    "a": ("compose:network",),
    "b": ("compose:network", "compose:volume"),
    "c": ("compose:volume",),
    "independent": (),
}
VERIFIED = FixtureObservation(True, True, True)
PROCESS_STOPPED = FixtureObservation(True, False, False)
WAIT = 15


def contend(path, role, barrier, results):
    gate = HostGate(path)
    barrier.wait(WAIT)
    try:
        if role == "remote":
            gate.admit_remote("a", "raced-remote")
            results.put((role, "GRANTED"))
        else:
            ticket = gate.request_update(UpdateKind(role))
            gate.enter_maintenance(ticket)
            results.put((role, "GRANTED"))
    except Denied as error:
        results.put((role, str(error)))


def kill_self():
    os.kill(os.getpid(), signal.SIGKILL)


class CrashBeforeCommitGate(HostGate):
    @contextmanager
    def _connect(self, **kwargs):
        with super()._connect(**kwargs) as db:
            db.set_trace_callback(self._before_statement)
            yield db

    @staticmethod
    def _before_statement(statement):
        if statement == "COMMIT":
            kill_self()


def crash_at(path, phase):
    gate = HostGate(path)
    if phase == "before-commit":
        CrashBeforeCommitGate(path).request_update(UpdateKind.APPLICATION)
        raise AssertionError("COMMIT hook did not kill the process")
    if phase == "remote":
        gate.admit_remote("a", "interrupted")
    else:
        ticket = gate.request_update(UpdateKind.APPLICATION)
        if phase in ("maintenance", "resuming"):
            gate.enter_maintenance(ticket)
        if phase == "resuming":
            gate.begin_resume(ticket)
    kill_self()


def crash_before_quarantine_commit(path):
    CrashBeforeCommitGate(path).record_quarantine("restart", decision_ref="fixture-decision")
    raise AssertionError("COMMIT hook did not kill the process")


def crash_before_activation_commit(path, evidence, signature, confirmation):
    CrashBeforeCommitGate(path).activate_recovery(evidence, signature, owner_confirmation=confirmation)
    raise AssertionError("COMMIT hook did not kill the process")


def fixture_daemon(accepted, release, finished):
    if not accepted.wait(WAIT) or not release.wait(WAIT):
        raise RuntimeError("Fixture daemon did not receive its signals")
    finished.set()


def fixture_helper(accepted):
    accepted.set()
    # SIGKILL must not strand a waiter on the daemon's shared condition.
    time.sleep(WAIT)
    raise RuntimeError("Fixture helper should have been killed")


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "gate.sqlite3"
        self.gate = HostGate.create(self.path, TOPOLOGY)
        self.ctx = multiprocessing.get_context("spawn")

    def start_process(self, target, *args):
        process = self.ctx.Process(target=target, args=args)
        process.start()
        self.addCleanup(self.stop_process, process)
        return process

    @staticmethod
    def stop_process(process):
        if process.is_alive():
            process.kill()
        process.join(WAIT)
        process.close()

    def test_race_remote_application_and_self_update_grants_one_permit(self):
        roles = ("remote", UpdateKind.APPLICATION.value, UpdateKind.SELF.value)
        barrier = self.ctx.Barrier(len(roles))
        results = self.ctx.Queue()
        self.addCleanup(results.close)
        processes = [self.start_process(contend, self.path, role, barrier, results) for role in roles]
        observed = dict(results.get(timeout=WAIT) for _ in roles)
        for process in processes:
            process.join(WAIT)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(set(observed), set(roles))
        self.assertEqual(list(observed.values()).count("GRANTED"), 1, observed)
        if observed["remote"] == "GRANTED":
            self.assertCountEqual(
                [observed[kind.value] for kind in UpdateKind], ["REMOTE_PERMIT_HELD", "GATE_CLOSED"]
            )
            self.assertEqual(self.gate.state(), GateState.QUIESCING)
        else:
            self.assertEqual(observed["remote"], "GATE_CLOSED")
            self.assertEqual(self.gate.state(), GateState.MAINTENANCE)

    def test_quiesce_blocks_new_work_and_waits_for_in_flight_attempt(self):
        permit = self.gate.admit_remote("a", "in-flight")
        ticket = self.gate.request_update(UpdateKind.APPLICATION)
        with self.assertRaisesRegex(Denied, "^GATE_CLOSED$"):
            self.gate.admit_remote("independent", "another")
        with self.assertRaisesRegex(Denied, "^REMOTE_PERMIT_HELD$"):
            self.gate.enter_maintenance(ticket)
        with self.assertRaisesRegex(Denied, "^INVALID_REMOTE_PERMIT$"):
            self.gate.report_remote(replace(permit, nonce="wrong"), VERIFIED)
        self.assertEqual(self.gate.report_remote(permit, VERIFIED), Outcome.SUCCEEDED)
        self.gate.enter_maintenance(ticket)
        with self.assertRaisesRegex(Denied, "^INVALID_UPDATE_TICKET$"):
            self.gate.enter_maintenance(ticket)
        self.gate.begin_resume(ticket)
        with self.assertRaisesRegex(Denied, "^GATE_CLOSED$"):
            self.gate.admit_remote("independent", "another")
        self.gate.complete_resume(ticket)
        next_ticket = self.gate.request_update(UpdateKind.SELF)
        self.assertGreater(next_ticket.epoch, ticket.epoch)
        with self.assertRaisesRegex(Denied, "^INVALID_UPDATE_TICKET$"):
            self.gate.enter_maintenance(ticket)
        with self.assertRaisesRegex(Denied, "^INVALID_UPDATE_TICKET$"):
            self.gate.enter_maintenance(replace(next_ticket, kind=UpdateKind.APPLICATION))
        self.gate.enter_maintenance(next_ticket)

    def test_unknown_during_drain_invalidates_update_ticket(self):
        permit = self.gate.admit_remote("a", "in-flight")
        ticket = self.gate.request_update(UpdateKind.SELF)
        self.assertEqual(self.gate.report_remote(permit, PROCESS_STOPPED), Outcome.UNKNOWN)
        self.assertEqual(self.gate.state(), GateState.RECOVERY_HOLD)
        with self.assertRaisesRegex(Denied, "^INVALID_UPDATE_TICKET$"):
            self.gate.enter_maintenance(ticket)

    def test_sigkill_before_quiesce_commit_rolls_back(self):
        process = self.start_process(crash_at, self.path, "before-commit")
        process.join(WAIT)
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        restarted = HostGate(self.path)
        self.assertEqual(restarted.recover_after_restart(), GateState.NORMAL)
        restarted.admit_remote("a", "after-crash")

    def test_sigkill_after_commit_recovers_into_hold(self):
        for phase, expected in (
            ("quiescing", GateState.QUIESCING),
            ("maintenance", GateState.MAINTENANCE),
            ("resuming", GateState.RESUMING),
            ("remote", GateState.NORMAL),
        ):
            with self.subTest(phase=phase):
                path = self.path.with_name(f"{phase}.sqlite3")
                HostGate.create(path, TOPOLOGY)
                process = self.start_process(crash_at, path, phase)
                process.join(WAIT)
                self.assertEqual(process.exitcode, -signal.SIGKILL)
                restarted = HostGate(path)
                self.assertEqual(restarted.state(), expected)
                self.assertEqual(restarted.recover_after_restart(), GateState.RECOVERY_HOLD)
                self.assertEqual(restarted.recover_after_restart(), GateState.RECOVERY_HOLD)
                if phase == "remote":
                    self.assertEqual(restarted.outcome("interrupted"), Outcome.UNKNOWN)
                with self.assertRaisesRegex(Denied, "^GATE_CLOSED$"):
                    restarted.admit_remote("independent", "after-crash")
                for kind in UpdateKind:
                    with self.assertRaisesRegex(Denied, "^GATE_CLOSED$"):
                        restarted.request_update(kind)

    def test_late_delegated_effect_after_helper_death_remains_unknown(self):
        permit = self.gate.admit_remote("a", "restart")
        accepted, release, finished = (self.ctx.Event() for _ in range(3))
        daemon = self.start_process(fixture_daemon, accepted, release, finished)
        helper = self.start_process(fixture_helper, accepted)
        self.assertTrue(accepted.wait(WAIT))
        helper.kill()
        helper.join(WAIT)
        self.assertEqual(helper.exitcode, -signal.SIGKILL)
        self.assertTrue(daemon.is_alive())
        self.assertFalse(finished.is_set())
        self.assertEqual(self.gate.report_remote(permit, PROCESS_STOPPED), Outcome.UNKNOWN)
        with self.assertRaisesRegex(Denied, "^OPEN_INCIDENT$"):
            self.gate.admit_remote("b", "conflict")
        release.set()
        self.assertTrue(finished.wait(WAIT))
        daemon.join(WAIT)
        self.assertEqual(daemon.exitcode, 0)
        with self.assertRaisesRegex(Denied, "^INVALID_REMOTE_PERMIT$"):
            self.gate.report_remote(permit, VERIFIED)
        self.assertEqual(self.gate.outcome("restart"), Outcome.UNKNOWN)

    def test_quarantine_covers_transitive_dependencies_after_reopen(self):
        permit = self.gate.admit_remote("a", "restart")
        self.gate.report_remote(permit, PROCESS_STOPPED)
        with self.assertRaisesRegex(Denied, "^OPEN_INCIDENT$"):
            self.gate.admit_remote("independent", "separate")
        with self.assertRaises(ValueError):
            self.gate.record_quarantine("restart", decision_ref=" ")
        affected = self.gate.record_quarantine("restart", decision_ref="fixture-decision")
        self.assertEqual(affected, {"a", "b", "c"})

        reopened = HostGate(self.path)
        for host in affected:
            with self.assertRaisesRegex(Denied, "^QUARANTINED$"):
                reopened.admit_remote(host, f"other-{host}")
        with self.assertRaisesRegex(Denied, "^OPERATION_ALREADY_ADMITTED$"):
            reopened.admit_remote("independent", "restart")
        separate = reopened.admit_remote("independent", "separate")
        self.assertEqual(reopened.report_remote(separate, VERIFIED), Outcome.SUCCEEDED)
        for kind in UpdateKind:
            with self.assertRaisesRegex(Denied, "^OPEN_INCIDENT$"):
                reopened.request_update(kind)

    def test_incomplete_inventory_keeps_global_reservation(self):
        path = self.path.with_name("incomplete.sqlite3")
        gate = HostGate.create(path, {**TOPOLOGY, "unknown": None})
        permit = gate.admit_remote("a", "restart")
        gate.report_remote(permit, PROCESS_STOPPED)
        with self.assertRaisesRegex(Denied, "^DEPENDENCIES_UNPROVEN$"):
            gate.record_quarantine("restart", decision_ref="fixture-decision")
        with self.assertRaisesRegex(Denied, "^OPEN_INCIDENT$"):
            gate.admit_remote("independent", "separate")

    def test_sigkill_before_quarantine_commit_keeps_global_reservation(self):
        permit = self.gate.admit_remote("a", "restart")
        self.gate.report_remote(permit, PROCESS_STOPPED)
        process = self.start_process(crash_before_quarantine_commit, self.path)
        process.join(WAIT)
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        reopened = HostGate(self.path)
        with self.assertRaisesRegex(Denied, "^OPEN_INCIDENT$"):
            reopened.admit_remote("independent", "separate")
        self.assertEqual(
            reopened.record_quarantine("restart", decision_ref="fixture-decision"),
            {"a", "b", "c"},
        )

    def test_open_never_recreates_a_missing_journal(self):
        missing = self.path.with_name("missing.sqlite3")
        with self.assertRaises(sqlite3.OperationalError):
            HostGate(missing).admit_remote("a", "attempt")
        self.assertFalse(missing.exists())
        with self.assertRaises(FileExistsError):
            HostGate.create(self.path, TOPOLOGY)


class RecoveryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / "restore.sqlite3"
        self.owner = SigningKey.generate()
        self.target = RecoveryTarget("old", "a" * 64, "new", "b" * 64, bytes(self.owner.verify_key))
        self.topology = {**TOPOLOGY, "offline": ()}
        self.gate = HostGate.create(self.path, self.topology, recovery=self.target)
        now = int(time.time())
        self.isolation = {
            "method": "power_off", "console": "host console", "operator": "owner",
            "autostart_blocked": True, "worker_isolated": True,
            "observations": [
                {"source": "power status", "at_utc": now - 12, "isolated": True},
                {"source": "console status", "at_utc": now - 1, "isolated": True},
            ],
        }
        self.checks = dict.fromkeys(
            ("database_integrity", "vault_integrity", "permissions_verified", "old_automation_disabled"), True,
        )
        self.reports = {
            host: {
                "evidence": f"fixture transcript for {host}", "reachable": True,
                "credentials_rotated": True, "old_key_denied": True, "new_key_verified": True,
                "old_key_sha256": "c" * 64, "new_key_sha256": "d" * 64,
                "direct_stopped": True, "delegated_terminal": True, "postconditions_verified": True,
            }
            for host in self.topology
        }
        self.reports["offline"] = {"evidence": "console unavailable", "reachable": False}

    def signed(self, *, target=None, isolation=None, checks=None, reports=None, signer=None):
        evidence = activation_attestation(
            target or self.target,
            isolation=self.isolation if isolation is None else isolation,
            checks=self.checks if checks is None else checks,
            hosts=self.reports if reports is None else reports,
        )
        return evidence, (signer or self.owner).sign(evidence).signature, hashlib.sha256(evidence).hexdigest()

    def activate(self, gate=None, **changes):
        evidence, signature, confirmation = self.signed(**changes)
        return (gate or self.gate).activate_recovery(evidence, signature, owner_confirmation=confirmation)

    def assert_read_only(self):
        reopened = HostGate(self.path)
        self.assertEqual(reopened.controller_mode(), ControllerMode.READ_ONLY_RECOVERY)
        with self.assertRaisesRegex(Denied, "^READ_ONLY_RECOVERY$"):
            reopened.admit_remote("independent", "ordinary-restart")
        for kind in UpdateKind:
            with self.assertRaisesRegex(Denied, "^READ_ONLY_RECOVERY$"):
                reopened.request_update(kind)

    def test_recovery_stays_read_only_after_reboot(self):
        original = HostGate.create(self.directory / "old.sqlite3", self.topology)
        self.assertEqual(original.controller_mode(), ControllerMode.ACTIVE)
        original.admit_remote("independent", "old-restart")
        self.assert_read_only()
        self.assertEqual(self.gate.recover_after_restart(), GateState.NORMAL)
        self.assert_read_only()

    def test_activation_persists_allowed_scope_and_quarantines_pending_effects(self):
        self.reports["a"]["delegated_terminal"] = False
        self.assertEqual(self.activate(), {"independent"})
        reopened = HostGate(self.path)
        self.assertEqual(reopened.controller_mode(), ControllerMode.ACTIVE)
        for host in ("a", "b", "c", "offline"):
            with self.subTest(host=host), self.assertRaisesRegex(Denied, "^QUARANTINED$"):
                reopened.admit_remote(host, f"restart-{host}")
        permit = reopened.admit_remote("independent", "ordinary-restart")
        self.assertEqual(reopened.report_remote(permit, VERIFIED), Outcome.SUCCEEDED)
        for kind in UpdateKind:
            with self.assertRaisesRegex(Denied, "^RECOVERY_QUARANTINE$"):
                reopened.request_update(kind)
        with self.assertRaisesRegex(Denied, "^RECOVERY_NOT_PENDING$"):
            self.activate(gate=reopened)

    def test_activation_requires_the_local_confirmation_signature_and_binding(self):
        evidence, signature, _ = self.signed()
        with self.assertRaisesRegex(Rejected, "^ACTIVATION_CONFIRMATION_REQUIRED$"):
            self.gate.activate_recovery(evidence, signature, owner_confirmation="0" * 64)
        with self.assertRaisesRegex(Rejected, "^ACTIVATION_SIGNATURE$"):
            self.activate(signer=SigningKey.generate())
        for field in ("old_controller_id", "old_host_key_sha256", "recovery_controller_id", "backup_manifest_sha256"):
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "^WRONG_ACTIVATION_BINDING$"):
                self.activate(target=replace(self.target, **{field: "e" * 64}))
        self.assert_read_only()

    def test_signed_timeout_or_incomplete_observations_do_not_allow_activation(self):
        for change in ({"method": "ssh_timeout"}, {"autostart_blocked": False}, {"worker_isolated": False}):
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, "^ISOLATION_EVIDENCE_REQUIRED$"):
                self.activate(isolation={**self.isolation, **change})
        first, second = self.isolation["observations"]
        for observations in ([first], [first, {**second, "source": first["source"]}],
                             [first, {**second, "at_utc": first["at_utc"] + 9}]):
            with self.subTest(observations=observations), self.assertRaisesRegex(Rejected, "^ISOLATION_OBSERVATIONS_REQUIRED$"):
                self.activate(isolation={**self.isolation, "observations": observations})
        self.assert_read_only()

    def test_integrity_inventory_and_rotation_are_required(self):
        with self.assertRaisesRegex(Rejected, "^RECOVERY_CHECKS_REQUIRED$"):
            self.activate(checks={**self.checks, "vault_integrity": False})
        with self.assertRaisesRegex(Rejected, "^RECOVERY_INVENTORY_MISMATCH$"):
            self.activate(reports={host: report for host, report in self.reports.items() if host != "offline"})
        for change in ({"old_key_denied": False}, {"new_key_verified": False}, {"new_key_sha256": "c" * 64}):
            reports = {**self.reports, "a": {**self.reports["a"], **change}}
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, "^CREDENTIAL_ROTATION_REQUIRED$"):
                self.activate(reports=reports)
        self.assert_read_only()

    def test_incomplete_dependencies_prevent_scoped_activation(self):
        self.path = self.directory / "incomplete.sqlite3"
        self.gate = HostGate.create(self.path, {**self.topology, "a": None}, recovery=self.target)
        with self.assertRaisesRegex(Denied, "^DEPENDENCIES_UNPROVEN$"):
            self.activate()
        self.assert_read_only()

    def test_activation_requires_a_safe_target_and_allows_update_after_full_verification(self):
        unavailable = dict.fromkeys(self.topology, {"evidence": "console unavailable", "reachable": False})
        with self.assertRaisesRegex(Denied, "^NO_SAFE_RECOVERY_TARGETS$"):
            self.activate(reports=unavailable)
        self.assert_read_only()
        self.reports["offline"] = {**self.reports["a"], "evidence": "offline host is now reachable and verified"}
        self.assertEqual(self.activate(), set(self.topology))
        ticket = self.gate.request_update(UpdateKind.APPLICATION)
        self.gate.enter_maintenance(ticket)
        self.assertEqual(self.gate.state(), GateState.MAINTENANCE)

    def test_sigkill_before_activation_commit_keeps_recovery_read_only(self):
        process = multiprocessing.get_context("spawn").Process(
            target=crash_before_activation_commit, args=(self.path, *self.signed()),
        )
        process.start()
        self.addCleanup(AdmissionTests.stop_process, process)
        process.join(WAIT)
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        self.assert_read_only()
        self.assertEqual(self.activate(), {"a", "b", "c", "independent"})


if __name__ == "__main__":
    unittest.main()
