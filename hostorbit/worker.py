"""One process owns a durable queue claim. All SSH use goes through protected local IPC."""

from threading import Event

from .database import identifier
from .errors import Denied
from .queue import JobQueue
from .runtime.protocol import checksum, fields, integer, text
from .runtime.storage import process_lock


class Worker:
    def __init__(self, queue: JobQueue, gate, broker, *, secret_refs, observe=None):
        self.queue, self.gate, self.broker = queue, gate, broker
        self.secret_refs = secret_refs
        self.id = identifier()
        self.observe = observe or (lambda _: None)

    def _recover_result(self, row):
        if row["status"] not in ("QUEUED", "INTENT_PREPARED"):
            return "UNKNOWN_OUTCOME"
        try:
            status = self.gate.call("attempt.status", {"job_id": row["id"]})
            if status["state"] == "ISSUED":
                self.gate.call("permit.cancel", {"job_id": row["id"], "nonce": status["nonce"]})
                return "CANCELLED_SAFE"
            if status["state"] == "CANCELLED_SAFE":
                return "CANCELLED_SAFE"
        except Denied as error:
            if error.code == "ATTEMPT_NOT_FOUND":
                return "CANCELLED_SAFE"
        return "UNKNOWN_OUTCOME"

    def run_one(self):
        try:
            claimed = self.queue.claim(self.id)
        except Denied as error:
            if error.code in {"WRITER_ADMISSION_CLOSED", "WRITER_BARRIER_TIMEOUT"}:
                return False
            raise
        if claimed is None:
            return False
        claim, row = claimed
        sent = False
        permit = None
        try:
            permit = self.gate.call("permit.admit", self.queue.binding(row))
            self.queue.advance(claim, "INTENT_PREPARED", permit=permit)
            self.observe("INTENT_PREPARED")
            # This commit must precede even entering the Broker dispatch path.
            self.queue.advance(claim, "DISPATCHING")
            self.observe("DISPATCHING")
            sent = True
            response = self.broker.call("use_for_scoped_ssh", {"permit": permit, "secret_ref": self.secret_refs[row["resource_id"]]})
            self.queue.advance(claim, "EXECUTING")
            self.queue.advance(claim, "VERIFYING")
            self.observe("VERIFYING")
            fields(response, ("outcome", "code", "observation", "authority_receipt"))
            result = {k: response[k] for k in ("outcome", "code", "observation")}
            receipt = self.gate.call("attempt.status", {"job_id": row["id"]})
            if (receipt != response["authority_receipt"] or receipt["state"] != response["outcome"]
                    or receipt["result_digest"] != checksum(result)):
                raise Denied("BROKER_RECEIPT_INVALID")
            text(response["code"], r"[A-Z][A-Z0-9_]{1,63}")
            if response["outcome"] == "SUCCEEDED":
                value = fields(response["observation"], ("status", "source", "observed_at", "boot_id"))
                if value["status"] != "REACHABLE" or value["source"] != "restricted_helper":
                    raise Denied("BROKER_OBSERVATION_INVALID")
                integer(value["observed_at"], int(self.queue.clock()) - 300, int(self.queue.clock()) + 2)
                text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                self.queue.finish(claim, "SUCCEEDED", response["code"], result=value)
            elif response["outcome"] in ("FAILED", "UNKNOWN_OUTCOME") and response["observation"] is None:
                self.queue.finish(claim, response["outcome"], response["code"])
            else:
                raise Denied("BROKER_OBSERVATION_INVALID")
        except Denied as error:
            if not sent and permit is not None:
                self.gate.call("permit.cancel", {"job_id": row["id"], "nonce": permit["claims"]["nonce"]})
            # A lost reply after dispatch never becomes success and never causes an automatic retry.
            self.queue.finish(claim, "UNKNOWN_OUTCOME" if sent else "CANCELLED_SAFE", error.code)
        return True

    def run(self, *, once=False, stop=None):
        stop = stop if stop is not None else Event()
        path = self.queue.store.path.with_suffix(".worker.lock")
        with process_lock(path, shared_gid=self.queue.store.access.shared_gid):
            self.queue.recover(self._recover_result)
            while not stop.is_set():
                found = self.run_one()
                if once:
                    return found
                if not found:
                    stop.wait(0.5)
            return False
