import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import errno
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import subprocess
import tempfile
from threading import Event
import time
import unittest

from nacl.secret import Aead
from nacl.signing import SigningKey

from stage0.journal import connect_journal
from stage0.recovery import SignedBackup, accept_bundle, issue_request, prepare_bundle
from stage0.snapshot import BackupDenied, BackupLab, Phase, Work, secret_context


WAIT = 15
PRE_CAPTURE = (Phase.REQUESTED, Phase.CLOSING_ADMISSION, Phase.SHORT_BARRIER)
POST_CAPTURE = (Phase.BARRIER_RELEASED, Phase.SEALED, Phase.SIGNED, Phase.UPLOADING)


def age_key(path):
    subprocess.run(["age-keygen", "-o", str(path)], capture_output=True, check=True, timeout=15)
    return subprocess.check_output(["age-keygen", "-y", str(path)], timeout=15).decode().strip()


def publish_locally(root, backup_id, backup):
    staging = root / f"{backup_id}.partial"
    staging.mkdir()
    (staging / "ciphertext.age").write_bytes(backup.ciphertext)
    (staging / "envelope.json").write_bytes(backup.envelope)
    (staging / "signature").write_bytes(backup.signature)
    ciphertext_hash = hashlib.sha256((staging / "ciphertext.age").read_bytes()).hexdigest()
    if ciphertext_hash != json.loads(backup.envelope)["ciphertext_sha256"]:
        raise RuntimeError("Fixture publication check failed")
    receipt = hashlib.sha256((staging / "envelope.json").read_bytes()).hexdigest()
    staging.rename(root / backup_id)
    return receipt


def crash_backup(root, out, wrapping_key, recipient, phase):
    def stop_at(_, current):
        if current == phase:
            os.kill(os.getpid(), signal.SIGKILL)

    BackupLab(root, wrapping_key).run(
        recipient, SigningKey.generate(), lambda backup_id, backup: publish_locally(out, backup_id, backup),
        observe=stop_at,
    )
    raise AssertionError("Fault was not injected")


def metadata(root):
    with connect_journal(root / "controller.sqlite3") as db:
        db.execute("BEGIN")
        return {table: [list(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in ("secret_refs", "generations", "resources", "revocations", "audit", "work")}


def churn(root, wrapping_key, stop, progressed):
    lab = BackupLab(root, wrapping_key)
    counts = {kind: 0 for kind in (Work.ROTATION, Work.REVOKE, Work.RESOURCE)}
    # Every completed cycle changes a resource and revokes the exact just-used
    # secret version. Rotation then creates a usable new version, retaining the
    # revocation history and another old, still-needed DEK generation.
    cycle = 0
    while not stop.is_set():
        for kind in counts:
            while not stop.is_set():
                try:
                    work = lab.admit(kind)
                    break
                except BackupDenied as error:
                    if str(error) != "BUSINESS_ADMISSION_CLOSED":
                        raise
                    stop.wait(0.002)
            else:
                return counts
            lab.checkpoint(work)
            if kind == Work.ROTATION:
                lab.finish_rotation(work, "changing", f"cycle-{cycle}".encode("ascii"))
            elif kind == Work.REVOKE:
                lab.finish_revoke(work, "changing")
            else:
                lab.finish_resource(work, "managed", "retained")
            counts[kind] += 1
        cycle += 1
        lab.collect_unused()
        progressed.set()
        stop.wait(0.003)
    return counts


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.controller = self.directory / "controller"
        self.controller.mkdir()
        self.out = self.directory / "receiver"
        self.out.mkdir()
        self.wrapping_key = secrets.token_bytes(Aead.KEY_SIZE)
        self.lab = BackupLab.create(self.controller, self.wrapping_key)
        self.offline_identity = self.directory / "owner.agekey"
        self.recipient = age_key(self.offline_identity)
        self.signing_key = SigningKey.generate()

    def rotate(self, name, value):
        self.lab.finish_rotation(self.lab.admit(Work.ROTATION), name, value)

    def run_backup(self, *, publish=None, **kwargs):
        if publish is None:
            publish = lambda backup_id, backup: publish_locally(self.out, backup_id, backup)
        return self.lab.run(self.recipient, self.signing_key, publish, **kwargs)

    def controller_rows(self, query, parameters=()):
        with connect_journal(self.controller / "controller.sqlite3") as db:
            return [tuple(row) for row in db.execute(query, parameters)]

    def backups(self):
        return self.controller_rows("SELECT id, phase, reason FROM backups ORDER BY rowid")

    def assert_released(self):
        self.assertEqual(self.controller_rows("SELECT digest FROM pins"), [])
        self.lab.finish_job(self.lab.admit(Work.JOB))

    def test_job_and_rotation_drain_then_network_failure_does_not_hold_barrier(self):
        self.rotate("managed", b"pre-drain")
        job = self.lab.admit(Work.JOB)
        rotation = self.lab.admit(Work.ROTATION)
        closing_admission, uploading, finish_upload = Event(), Event(), Event()

        def observe(_, phase):
            if phase == Phase.CLOSING_ADMISSION:
                closing_admission.set()
            if phase == Phase.SHORT_BARRIER:
                with self.assertRaisesRegex(BackupDenied, "^BUSINESS_ADMISSION_CLOSED$"):
                    self.lab.admit(Work.JOB)

        def failed_sftp(_, __):
            uploading.set()
            if not finish_upload.wait(WAIT):
                raise TimeoutError("Fixture network was not released")
            raise OSError(errno.EHOSTUNREACH, "fixture destination")

        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(self.run_backup, observe=observe, publish=failed_sftp)
            try:
                self.assertTrue(closing_admission.wait(WAIT))
                with self.assertRaisesRegex(BackupDenied, "^BUSINESS_ADMISSION_CLOSED$"):
                    self.lab.admit(Work.JOB)
                self.lab.checkpoint(job)
                self.lab.checkpoint(rotation)
                self.lab.finish_job(job)
                self.lab.finish_rotation(rotation, "managed", b"captured")
                self.assertTrue(uploading.wait(WAIT))

                self.assertEqual(self.backups()[-1][1], Phase.UPLOADING)
                self.assertEqual(self.controller_rows(
                    "SELECT event FROM audit WHERE work_id = ? ORDER BY seq", (job,),
                ), [("admitted",), ("checkpoint",), ("completed",)])
                pins = {row[0] for row in self.controller_rows("SELECT digest FROM pins")}
                self.assertEqual(len(pins), 2)
                self.rotate("managed", b"after-release")
                self.assertTrue(pins.isdisjoint(self.lab.collect_unused()))
                with self.assertRaisesRegex(BackupDenied, "^BACKUP_ACTIVE$"):
                    self.run_backup()
            finally:
                finish_upload.set()
            with self.assertRaises(OSError) as failure:
                pending.result(WAIT)
            self.assertEqual(failure.exception.errno, errno.EHOSTUNREACH)

        self.assertEqual(self.backups()[-1][1:], (Phase.FAILED, "OSError"))
        self.assertTrue(pins.issubset(self.lab.collect_unused()))
        self.assertEqual(list(self.out.iterdir()), [])
        self.assert_released()

    def test_published_archive_restores_multiple_dek_generations_without_old_controller(self):
        self.rotate("old", b"old-generation")
        self.rotate("current", b"superseded")
        self.rotate("current", b"new-generation")
        job = self.lab.admit(Work.JOB)
        self.lab.checkpoint(job)
        self.lab.finish_job(job)
        published_id = self.run_backup()
        self.assertEqual(self.backups()[-1][1:], (Phase.PUBLISHED, None))
        self.assert_released()

        directory = self.out / published_id
        backup = SignedBackup(
            (directory / "ciphertext.age").read_bytes(),
            (directory / "envelope.json").read_bytes(),
            (directory / "signature").read_bytes(),
        )
        for path in self.controller.iterdir():
            path.unlink()
        self.controller.rmdir()
        target = self.directory / "new-controller"
        target.mkdir()
        transport = target / "transport.agekey"
        age_key(transport)
        ledger = target / "recovery.sqlite3"
        request = issue_request(
            ledger, target_id="fresh-controller", transport_identity=transport,
            source_envelope_sha256=backup.envelope_sha256,
        )
        bundle, review = prepare_bundle(backup, self.signing_key.verify_key, self.offline_identity, request)
        self.offline_identity.unlink()
        restored = accept_bundle(ledger, transport, bundle, owner_digest=review.bundle_sha256)

        payload = json.loads(restored.deks)
        with closing(sqlite3.connect(":memory:")) as db:
            db.deserialize(restored.database)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute("SELECT count(*) FROM work").fetchone(), (0,))
            self.assertEqual(db.execute("SELECT event FROM audit ORDER BY seq DESC LIMIT 1").fetchone(), ("completed",))
            references = db.execute("SELECT name, version, ciphertext FROM secret_refs").fetchall()
        self.assertEqual(set(payload["keys"]), {str(version) for _, version, _ in references})
        self.assertEqual(len(payload["keys"]), 2)
        actual = {}
        for name, version, ref in references:
            key = base64.b64decode(payload["keys"][str(version)])
            ciphertext = base64.b64decode(payload["ciphertexts"][ref])
            actual[name] = Aead(key).decrypt(ciphertext, secret_context(name, version))
        self.assertEqual(actual, {"old": b"old-generation", "current": b"new-generation"})

    def test_deadlines_abort_and_release_admission(self):
        work = self.lab.admit(Work.JOB)
        with self.assertRaisesRegex(BackupDenied, "^DRAIN_TIMEOUT$"):
            self.run_backup(drain_seconds=0.03)
        self.assertEqual(self.backups()[-1][1:], (Phase.ABORTED, "DRAIN_TIMEOUT"))
        self.lab.checkpoint(work)
        self.lab.finish_job(work)
        self.assert_released()

        def stall_snapshot(_, phase):
            if phase == Phase.SHORT_BARRIER:
                time.sleep(0.05)

        with self.assertRaisesRegex(BackupDenied, "^SNAPSHOT_TIMEOUT$"):
            self.run_backup(barrier_seconds=0.01, observe=stall_snapshot)
        self.assertEqual(self.backups()[-1][1:], (Phase.ABORTED, "SNAPSHOT_TIMEOUT"))
        self.assert_released()

    def test_no_publication_without_a_verified_receipt(self):
        with self.assertRaisesRegex(BackupDenied, "^PUBLICATION_UNVERIFIED$"):
            self.run_backup(publish=lambda *_: "wrong-digest")
        self.assertEqual(self.backups()[-1][1:], (Phase.FAILED, "PUBLICATION_UNVERIFIED"))
        self.assert_released()

    def test_corrupt_vault_object_aborts_before_packaging(self):
        self.rotate("fixture", b"value")
        ref, = self.controller_rows("SELECT ciphertext FROM secret_refs")[0]
        with connect_journal(self.controller / "vault.sqlite3") as vault:
            vault.execute("UPDATE objects SET data = ? WHERE digest = ?", (b"corrupt", ref))
        with self.assertRaisesRegex(BackupDenied, "^VAULT_OBJECT_MISSING_OR_CORRUPT$"):
            self.run_backup()
        self.assertEqual(
            self.backups()[-1][1:], (Phase.ABORTED, "VAULT_OBJECT_MISSING_OR_CORRUPT")
        )
        self.assertEqual(list(self.out.iterdir()), [])
        self.assert_released()

    def test_enospc_injection_at_each_active_phase(self):
        self.rotate("fixture", b"value")
        for failed_phase in PRE_CAPTURE + POST_CAPTURE:
            with self.subTest(phase=failed_phase):
                def no_space(_, phase):
                    if phase == failed_phase:
                        raise OSError(errno.ENOSPC, "fixture full")

                with self.assertRaises(OSError) as failure:
                    self.run_backup(observe=no_space)
                self.assertEqual(failure.exception.errno, errno.ENOSPC)
                expected = Phase.ABORTED if failed_phase in PRE_CAPTURE else Phase.FAILED
                self.assertEqual(self.backups()[-1][1:], (expected, "OSError"))
                self.assert_released()
        self.assertEqual(list(self.out.iterdir()), [])

    def test_sigkill_at_each_phase_recovers_without_exposing_partial_snapshots(self):
        self.rotate("fixture", b"value")
        ctx = multiprocessing.get_context("spawn")
        for phase in PRE_CAPTURE + POST_CAPTURE + (Phase.PUBLISHED,):
            with self.subTest(phase=phase):
                process = ctx.Process(
                    target=crash_backup, args=(self.controller, self.out, self.wrapping_key, self.recipient, phase),
                )
                process.start()
                try:
                    process.join(WAIT)
                    self.assertEqual(process.exitcode, -signal.SIGKILL)
                finally:
                    if process.is_alive():
                        process.kill()
                        process.join(WAIT)
                    process.close()
                self.assertEqual(self.backups()[-1][1], phase)
                self.lab.recover_interrupted()
                backup_id, actual, reason = self.backups()[-1]
                if phase == Phase.PUBLISHED:
                    self.assertEqual((actual, reason), (Phase.PUBLISHED, None))
                    self.assertTrue((self.out / backup_id / "ciphertext.age").is_file())
                else:
                    terminal = Phase.ABORTED if phase in PRE_CAPTURE else Phase.FAILED
                    self.assertEqual((actual, reason), (terminal, "INTERRUPTED"))
                    self.assertFalse((self.out / backup_id).exists())
                self.assert_released()

    def assert_archive_matches_capture(self, backup_id, expected):
        directory = self.out / backup_id
        backup = SignedBackup(*(directory.joinpath(name).read_bytes()
                                for name in ("ciphertext.age", "envelope.json", "signature")))
        target = self.directory / f"restore-{backup_id}"
        target.mkdir()
        identity = target / "transport.agekey"
        age_key(identity)
        request = issue_request(target / "recovery.sqlite3", target_id=backup_id,
                                transport_identity=identity, source_envelope_sha256=backup.envelope_sha256)
        bundle, review = prepare_bundle(backup, self.signing_key.verify_key, self.offline_identity, request)
        restored = accept_bundle(target / "recovery.sqlite3", identity, bundle, owner_digest=review.bundle_sha256)
        payload = json.loads(restored.deks)
        with closing(sqlite3.connect(":memory:")) as db:
            db.deserialize(restored.database)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            actual = {table: [list(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")]
                      for table in expected}
        self.assertEqual(actual, expected)
        self.assertEqual(actual["work"], [])
        self.assertTrue(actual["revocations"])
        self.assertTrue(actual["resources"])
        self.assertEqual(set(payload["keys"]), {str(row[1]) for row in actual["secret_refs"]})
        self.assertEqual(set(payload["ciphertexts"]), {row[2] for row in actual["secret_refs"]})
        for name, version, ref in actual["secret_refs"]:
            encrypted = base64.b64decode(payload["ciphertexts"][ref])
            self.assertEqual(hashlib.sha256(encrypted).hexdigest(), ref)
            value = Aead(base64.b64decode(payload["keys"][str(version)])).decrypt(
                encrypted, secret_context(name, version))
            self.assertTrue(value == b"old-needed" if name == "retained" else value.startswith(b"cycle-"))

    def test_continuous_rotation_revoke_and_resource_changes_restore_captured_audit_head(self):
        self.rotate("retained", b"old-needed")
        stop, progressed = Event(), Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            writer = pool.submit(churn, self.controller, self.wrapping_key, stop, progressed)
            try:
                self.assertTrue(progressed.wait(WAIT))
                for _ in range(3):
                    captured = {}

                    def observe(_, phase):
                        if phase == Phase.SHORT_BARRIER:
                            captured.update(metadata(self.controller))
                        if phase == Phase.BARRIER_RELEASED:
                            progressed.clear()
                            self.assertTrue(progressed.wait(WAIT))

                    backup_id = self.run_backup(observe=observe)
                    self.assert_archive_matches_capture(backup_id, captured)
                    self.assertGreater(len(metadata(self.controller)["audit"]), len(captured["audit"]))
            finally:
                stop.set()
            self.assertTrue(all(value > 3 for value in writer.result(WAIT).values()))
        self.assert_released()

    def test_revocation_blocks_new_binding_but_rotation_can_create_a_new_usable_version(self):
        self.rotate("changing", b"before-revocation")
        old_version = self.controller_rows("SELECT version FROM secret_refs")[0][0]
        self.lab.finish_revoke(self.lab.admit(Work.REVOKE), "changing")
        resource = self.lab.admit(Work.RESOURCE)
        with self.assertRaisesRegex(BackupDenied, "^SECRET_REVOKED$"):
            self.lab.finish_resource(resource, "managed", "changing")
        self.assertEqual(self.controller_rows("SELECT * FROM resources"), [])
        self.rotate("changing", b"after-revocation")
        self.lab.finish_resource(resource, "managed", "changing")
        self.assertEqual(self.controller_rows("SELECT * FROM revocations"), [("changing", old_version)])
        self.assertEqual(self.controller_rows("SELECT * FROM resources"), [("managed", 1, "changing")])
        self.assert_released()

    def test_continuous_mutations_and_sigkill_matrix_only_restore_published_archives(self):
        self.rotate("retained", b"old-needed")
        ctx = multiprocessing.get_context("spawn")
        stop, progressed = Event(), Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            writer = pool.submit(churn, self.controller, self.wrapping_key, stop, progressed)
            try:
                self.assertTrue(progressed.wait(WAIT))
                for phase in PRE_CAPTURE + POST_CAPTURE + (Phase.PUBLISHED,):
                    with self.subTest(phase=phase):
                        # Use our persistent signer so every surviving archive can
                        # undergo independent signature/bundle/restore checks.
                        process = ctx.Process(target=crash_churning_backup, args=(
                            self.controller, self.out, self.wrapping_key, self.recipient,
                            bytes(self.signing_key), phase))
                        process.start()
                        try:
                            process.join(WAIT)
                            self.assertEqual(process.exitcode, -signal.SIGKILL)
                        finally:
                            if process.is_alive():
                                process.kill()
                                process.join(WAIT)
                            process.close()
                        self.lab.recover_interrupted()
                        backup_id, terminal, _ = self.backups()[-1]
                        if phase == Phase.PUBLISHED:
                            self.assertEqual(terminal, Phase.PUBLISHED)
                            self.assert_archive_matches_capture(
                                backup_id, json.loads((self.out / "captured-state.json").read_text()))
                        else:
                            self.assertIn(terminal, (Phase.ABORTED, Phase.FAILED))
                            self.assertFalse((self.out / backup_id).exists())
                        self.assertEqual(self.controller_rows("SELECT digest FROM pins"), [])
                self.assertEqual(len([p for p in self.out.iterdir() if p.is_dir()]), 1)
            finally:
                stop.set()
            self.assertTrue(all(value > 0 for value in writer.result(WAIT).values()))
        self.assert_released()


def crash_churning_backup(root, out, wrapping_key, recipient, signing_key, phase):
    def observe(_, current):
        if current == Phase.SHORT_BARRIER:
            (out / "captured-state.json").write_text(json.dumps(metadata(root)), encoding="utf-8")
        if current == phase:
            os.kill(os.getpid(), signal.SIGKILL)

    BackupLab(root, wrapping_key).run(
        recipient, SigningKey(signing_key), lambda backup_id, backup: publish_locally(out, backup_id, backup),
        observe=observe)
    raise AssertionError("Fault was not injected")
