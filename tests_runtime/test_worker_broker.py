import json
import os
from pathlib import Path
import tempfile
from threading import Event
import time
import unittest

from hostorbit.auth import AuthService
from hostorbit.admission import Admission
from hostorbit.database import Store
from hostorbit.errors import Denied
from hostorbit.queue import JobQueue
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.broker import Broker
from hostorbit.runtime.ipc import Peer
from hostorbit.runtime.protocol import canonical
from hostorbit.runtime.storage import new_private_file, process_lock
from hostorbit.runtime.vault import Vault
from hostorbit.worker import Worker
from fixtures import ACTOR, BROKER_UID, PASSWORD, SECRET, TARGET, WORKER_UID, observation, policy, private_key


class LocalClient:
    """In-process contract tests; the separate CI lab verifies kernel credentials and UID isolation."""
    def __init__(self, service, role, uid):
        self.service, self.role, self.uid = service, role, uid

    def call(self, operation, payload):
        return self.service.dispatch(self.role, Peer(42, self.uid, self.uid), operation, payload)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.writers = Admission.initialize(self.directory / "writers", owner=os.geteuid())
        self.writers.publish("OPEN")
        self.store = Store.initialize(self.directory / "app" / "controller.sqlite3")
        self.store.writers = self.writers
        self.auth = AuthService(self.store)
        self.owner = self.auth.create_owner(self.auth.issue_bootstrap(), "roman", PASSWORD)
        self.tokens = self.auth.login("roman", PASSWORD, ip="fixture", correlation="fixture")[0]
        self.policy = policy()
        self.queue = JobQueue(self.store)
        self.queue.register_resource(TARGET, self.policy.targets[TARGET].scope_digest, 1)
        self.authority = Authority.initialize(self.directory / "gate", self.policy)
        self.authority.journal.writers = self.writers
        key = self.directory / "dek"
        new_private_file(key, os.urandom(32))
        self.vault = Vault.initialize(self.directory / "vault", key)
        self.vault.journal.writers = self.writers
        self.vault.import_ssh(SECRET, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        Broker.initialize(self.directory / "broker", self.policy)
        self.executions = []
        def execute(target, key, known_hosts):
            self.assertEqual(key, private_key())
            self.executions.append(target.id)
            return observation()
        self.broker = Broker(self.directory / "broker", self.policy, self.vault,
                             LocalClient(self.authority, "broker", BROKER_UID), bytes(self.authority.key.verify_key),
                             worker_uid=WORKER_UID, execute=execute, writers=self.writers)
        self.worker = Worker(self.queue, LocalClient(self.authority, "worker", WORKER_UID),
                             LocalClient(self.broker, "worker", WORKER_UID), secret_refs={TARGET: SECRET + ":v1"})

    def enqueue(self, key="fixture-request-0001"):
        return self.queue.enqueue_probe(self.auth, self.tokens.session, self.tokens.csrf, TARGET, key)

    def job(self, job_id):
        return self.queue.get(self.auth, self.tokens.session, job_id)[0]

    def test_committed_job_reaches_broker_without_returning_key_material(self):
        queued = self.enqueue()
        self.assertEqual(queued["status"], "QUEUED")
        self.worker.run(once=True)
        result = self.job(queued["id"])
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["result"]["status"], "REACHABLE")
        self.assertEqual(self.executions, [TARGET])
        self.assertEqual(self.enqueue()["id"], queued["id"])
        self.assertFalse(self.worker.run(once=True))
        self.store.verify_audit()
        with self.store.connect() as db:
            raw = "\n".join(db.iterdump())
        self.assertNotIn(private_key().decode(), raw)
        self.assertNotIn("PRIVATE KEY", json.dumps(result))

    def test_closing_during_active_job_allows_completion_without_claiming_more_work(self):
        first, second = self.enqueue(), self.enqueue("fixture-request-0002")
        with self.store.write() as db:
            db.execute("UPDATE jobs SET created_at=created_at+1 WHERE id=?", (second["id"],))
        self.worker.observe = lambda phase: self.writers.publish("CLOSING_ADMISSION", first["id"]) if phase == "INTENT_PREPARED" else None
        self.assertTrue(self.worker.run_one())
        self.assertEqual(self.job(first["id"])["status"], "SUCCEEDED")
        self.assertEqual(self.job(second["id"])["status"], "QUEUED")
        self.assertFalse(self.worker.run_one())
        with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
            self.enqueue("fixture-request-0003")
        with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
            self.vault.revoke(SECRET + ":v1")
        self.assertEqual(self.executions, [TARGET])
        self.store.verify_audit()
        # Login/logout, rate limits and audit are operational metadata, so the
        # Owner can still inspect the controller during the drain period.
        tokens = self.auth.login("roman", PASSWORD, ip="fixture", correlation="drain")[0]
        self.auth.logout(tokens.session, tokens.csrf, correlation="drain")

    def test_closed_admission_prevents_vault_object_creation_and_new_gate_permits(self):
        queued = self.enqueue()
        with self.store.read() as db:
            row = dict(db.execute("SELECT * FROM jobs WHERE id=?", (queued["id"],)).fetchone())
        before = set((self.vault.directory / "objects").iterdir())
        self.writers.publish("CLOSING_ADMISSION", queued["id"])
        with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
            self.vault.import_ssh(SECRET, 2, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.assertEqual(before, set((self.vault.directory / "objects").iterdir()))
        with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
            self.authority.admit(self.queue.binding(row))

    def test_stopped_worker_does_not_claim_a_waiting_job_and_releases_its_lifetime_lock(self):
        queued = self.enqueue()
        stop = Event()
        stop.set()
        self.assertFalse(self.worker.run(stop=stop))
        self.assertEqual(self.job(queued["id"])["status"], "QUEUED")
        self.assertEqual(self.executions, [])
        self.worker.run(once=True)
        self.assertEqual(self.job(queued["id"])["status"], "SUCCEEDED")

    def test_stop_during_an_accepted_job_finishes_it_without_claiming_the_next(self):
        first, second = self.enqueue(), self.enqueue("fixture-request-0002")
        with self.store.write() as db:
            db.execute("UPDATE jobs SET created_at=created_at+1 WHERE id=?", (second["id"],))
        stop = Event()
        def stopping(phase):
            if phase == "INTENT_PREPARED":
                stop.set()
        self.worker.observe = stopping
        self.worker.run(stop=stop)
        self.assertEqual(self.job(first["id"])["status"], "SUCCEEDED")
        self.assertEqual(self.job(second["id"])["status"], "QUEUED")
        self.assertEqual(self.executions, [TARGET])
        self.store.verify_audit()
        self.worker.run(once=True)
        self.assertEqual(self.job(second["id"])["status"], "SUCCEEDED")

    def test_permit_replay_and_revoke_before_use_never_repeat_ssh(self):
        queued = self.enqueue()
        self.worker.run(once=True)
        with self.store.connect() as db:
            permit = json.loads(db.execute("SELECT permit FROM jobs WHERE id=?", (queued["id"],)).fetchone()[0])
        with self.assertRaisesRegex(Denied, "PERMIT_REPLAY"):
            self.broker.use({"permit": permit, "secret_ref": SECRET + ":v1"}, Peer(42, WORKER_UID, WORKER_UID))
        second = self.enqueue("fixture-request-0002")
        self.vault.revoke(SECRET + ":v1")
        self.worker.run(once=True)
        self.assertEqual(self.job(second["id"])["status"], "UNKNOWN_OUTCOME")
        self.assertEqual(self.executions, [TARGET])

    def test_scope_changed_or_actor_revoked_after_enqueue_cancels_before_permit(self):
        queued = self.enqueue()
        with self.store.write() as db:
            db.execute("UPDATE resources SET policy_revision=2 WHERE id=?", (TARGET,))
        self.worker.run(once=True)
        self.assertEqual(self.job(queued["id"])["status"], "CANCELLED_SAFE")
        self.assertEqual(self.executions, [])
        with self.assertRaisesRegex(Denied, "ATTEMPT_NOT_FOUND"):
            self.authority.status(queued["id"])

    def test_crash_after_dispatch_is_terminal_unknown_and_not_retried(self):
        queued = self.enqueue()
        def crash(phase):
            if phase == "DISPATCHING":
                raise SystemExit("fixture worker power loss")
        self.worker.observe = crash
        with self.assertRaises(SystemExit):
            self.worker.run(once=True)
        self.worker.observe = lambda _: None
        self.assertFalse(self.worker.run(once=True))
        self.assertEqual(self.job(queued["id"])["status"], "UNKNOWN_OUTCOME")
        self.assertEqual(self.executions, [])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM job_incidents WHERE job_id=?", (queued["id"],)).fetchone()[0], "OPEN")

    def test_crash_before_dispatch_cancels_unconsumed_root_permit(self):
        queued = self.enqueue()
        def crash(phase):
            if phase == "INTENT_PREPARED":
                raise SystemExit("fixture worker loss")
        self.worker.observe = crash
        with self.assertRaises(SystemExit):
            self.worker.run(once=True)
        self.worker.observe = lambda _: None
        self.worker.run(once=True)
        self.assertEqual(self.job(queued["id"])["status"], "CANCELLED_SAFE")
        self.assertEqual(self.authority.status(queued["id"])["state"], "CANCELLED_SAFE")
        self.assertEqual(self.executions, [])

    def test_lost_broker_reply_is_unknown_even_if_authority_persisted_success(self):
        queued = self.enqueue()
        original = self.worker.broker
        class LostReply:
            def call(_, operation, payload):
                original.call(operation, payload)
                raise Denied("RPC_UNAVAILABLE", 503)
        self.worker.broker = LostReply()
        self.worker.run(once=True)
        self.assertEqual(self.job(queued["id"])["status"], "UNKNOWN_OUTCOME")
        self.assertEqual(self.authority.status(queued["id"])["state"], "SUCCEEDED")
        self.assertEqual(self.executions, [TARGET])
        self.assertFalse(self.worker.run(once=True))

    def test_second_worker_process_cannot_recover_live_claims(self):
        self.enqueue()
        with process_lock(self.store.path.with_suffix(".worker.lock")):
            with self.assertRaisesRegex(Denied, "PROCESS_ALREADY_RUNNING"):
                self.worker.run(once=True)
        self.assertEqual(self.executions, [])

    def test_vault_metadata_substitution_and_ciphertext_corruption_are_rejected(self):
        with self.vault.journal.write() as db:
            row = db.execute("SELECT metadata FROM secrets").fetchone()
            value = json.loads(row[0])
            value["owner_id"] = SECRET
            db.execute("UPDATE secrets SET metadata=?", (canonical(value).decode(),))
        with self.assertRaisesRegex(Denied, "CORRUPT"):
            self.vault.use_ssh(SECRET + ":v1", worker_uid=WORKER_UID, target=TARGET)

    def test_swapping_a_complete_secret_metadata_blob_pair_cannot_change_the_requested_reference(self):
        other = "01JCYQZ4T9V8MNVYEH3D2M7Q1E"
        self.vault.import_ssh(other, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        self.vault.revoke(other + ":v1")
        with self.vault.journal.write() as db:
            row = db.execute("SELECT metadata,object_digest FROM secrets WHERE ref=?", (other + ":v1",)).fetchone()
            db.execute("UPDATE secrets SET metadata=?,object_digest=? WHERE ref=?", (*row, SECRET + ":v1"))
        with self.assertRaisesRegex(Denied, "SECRET_SCOPE_DENIED"):
            self.vault.use_ssh(SECRET + ":v1", worker_uid=WORKER_UID, target=TARGET)

    def test_missing_runtime_key_does_not_create_a_partial_vault(self):
        root = self.directory / "not-created"
        with self.assertRaises(FileNotFoundError):
            Vault.initialize(root, self.directory / "missing-dek")
        self.assertFalse(root.exists())
