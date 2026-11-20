"""Scoped SSH-use with durable receipts, gate consumption and protected Vault policy."""

from pathlib import Path
import time

from ..errors import Denied
from .authority import verify_permit
from .protocol import ULID, canonical, checksum, decode, fields, text
from .ssh import probe, provision_known_hosts, restart, verify_known_hosts
from .storage import Journal


_SCHEMA = """
CREATE TABLE receipts(job_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
    permit TEXT NOT NULL, response TEXT);
"""


class Broker:
    def __init__(self, directory, policy, vault, gate, verify_key, *, worker_uid, execute=probe, execute_restart=restart, clock=time.time, writers=None):
        self.directory, self.policy = Path(directory), policy
        self.vault, self.gate, self.verify_key = vault, gate, verify_key
        self.worker_uid, self.execute, self.clock = worker_uid, execute, clock
        self.execute_restart = execute_restart
        self.journal = Journal(self.directory / "receipts.sqlite3", writers=writers)
        verify_known_hosts(self.directory / "known_hosts", policy)

    @classmethod
    def initialize(cls, directory, policy):
        Journal.initialize(Path(directory) / "receipts.sqlite3", _SCHEMA)
        provision_known_hosts(Path(directory) / "known_hosts", policy)

    def recover(self):
        # A restarted Broker never repeats a possibly sent request.
        with self.journal.connect() as db:
            rows = db.execute("SELECT * FROM receipts WHERE state IN ('PREPARED','DISPATCHING')").fetchall()
        for row in rows:
            permit = decode(row["permit"].encode())
            current = self.gate.call("attempt.status", {"job_id": row["job_id"]})
            if current["state"] == "DISPATCHING":
                self._complete(permit, "UNKNOWN_OUTCOME", "BROKER_RESTART", None)
            elif current["state"] == "ISSUED":
                self.gate.call("permit.cancel", {"job_id": row["job_id"], "nonce": row["nonce"]})
                self._persist(row["job_id"], "FAILED", {"outcome": "FAILED", "code": "BROKER_RESTART_BEFORE_DISPATCH", "observation": None})
            else:
                self._persist(row["job_id"], "UNKNOWN_OUTCOME", {"outcome": "UNKNOWN_OUTCOME", "code": "BROKER_RESTART", "observation": None})

    def _persist(self, job_id, state, response):
        with self.journal.write() as db:
            db.execute("UPDATE receipts SET state=?,response=? WHERE job_id=?", (state, canonical(response).decode(), job_id))

    def _complete(self, permit, outcome, code, observation):
        result = {"outcome": outcome, "code": code, "observation": observation}
        claims = permit["claims"]
        receipt = self.gate.call("attempt.complete", {"job_id": claims["job_id"], "nonce": claims["nonce"],
                                 "outcome": outcome, "result_code": code, "result_digest": checksum(result)})
        response = {**result, "authority_receipt": receipt}
        self._persist(claims["job_id"], outcome, response)
        return response

    def use(self, request, peer):
        by_policy = isinstance(request, dict) and "policy_ref" in request
        ref_field = "policy_ref" if by_policy else "secret_ref"
        fields(request, ("permit", ref_field))
        claims = verify_permit(request["permit"], self.verify_key, now=int(self.clock()))
        target = self.policy.target(claims["target"], claims["capability"], claims["scope_digest"])
        capability = claims["capability"]
        if capability == "host.probe" and not claims["mutating"]:
            anchor = target.value["secret_ref"]
        elif capability == "docker.restart" and claims["mutating"]:
            anchor = target.value["restart_secret_ref"]
        else:
            raise Denied("BROKER_SCOPE_DENIED")
        text(request[ref_field], ULID + r":v[1-9][0-9]{0,8}")
        if by_policy and request[ref_field] != anchor:
            raise Denied("BROKER_SCOPE_DENIED")
        # Key bytes stay in this Broker process and never enter RPC responses.
        with self.vault.key_lock(anchor, shared=True):
            key = self.vault.use_policy_key(anchor, consumer_uid=peer.uid, target=target.id, purpose=capability,
                                            scope_digest=target.scope_digest, policy_revision=target.revision,
                                            exact_ref=None if by_policy else request[ref_field])
            return self._dispatch_key(request, claims, target, key)

    def _dispatch_key(self, request, claims, target, key):
        with self.journal.write() as db:
            if db.execute("SELECT 1 FROM receipts WHERE job_id=? OR nonce=?", (claims["job_id"], claims["nonce"])).fetchone():
                raise Denied("PERMIT_REPLAY")
            db.execute("INSERT INTO receipts VALUES(?,?,'PREPARED',?,NULL)", (claims["job_id"], claims["nonce"], canonical(request["permit"]).decode()))
        self.gate.call("permit.consume", request["permit"])
        with self.journal.write() as db:
            db.execute("UPDATE receipts SET state='DISPATCHING' WHERE job_id=?", (claims["job_id"],))
        if claims["capability"] == "docker.restart":
            try:
                result = self.execute_restart(target, key, self.directory / "known_hosts", claims["restart"])
            except Denied as error:
                return self._complete(request["permit"], "UNKNOWN_OUTCOME", error.code, None)
            outcome = "FAILED" if result["outcome"] == "DENIED" else result["outcome"]
            return self._complete(request["permit"], outcome, result["code"], None)
        try:
            observation = self.execute(target, key, self.directory / "known_hosts")
            return self._complete(request["permit"], "SUCCEEDED", "PROBE_VERIFIED", observation)
        except Denied as error:
            # The only installed operation is read-only, with no delegated effects.
            return self._complete(request["permit"], "FAILED", error.code, None)

    def dispatch(self, role, peer, operation, payload):
        if role != "worker" or peer.uid != self.worker_uid:
            raise Denied("RPC_PEER_DENIED")
        if operation == "use_for_scoped_ssh":
            return self.use(payload, peer)
        if operation == "receipt.get":
            fields(payload, ("job_id",))
            text(payload["job_id"], ULID)
            with self.journal.connect() as db:
                row = db.execute("SELECT response FROM receipts WHERE job_id=?", (payload["job_id"],)).fetchone()
                if row is None or row["response"] is None:
                    raise Denied("RECEIPT_NOT_TERMINAL")
                return decode(row["response"].encode())
        raise Denied("RPC_OPERATION_DENIED")
