"""Apply a reviewed Controller API/Worker update and SQLite migration locally."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import secrets
import sqlite3
import stat
import sys
import time

from deploy.artifact import ArtifactError, trusted_key
from deploy.controller_restore_attestation import MAX_EVIDENCE
from deploy.prepare_migration import prepare_migration
from deploy.supervised_update import check_gate, enter_maintenance, private_slots
from deploy.update_release import verify_candidate
from hostorbit.admission import Admission
from hostorbit.database import DataAccess, Store
from hostorbit.errors import Denied
from hostorbit.migrations import _source_digest, _statements, _verify, migration_script
from hostorbit.runtime.activation import atomic
from hostorbit.runtime.cli import configuration
from hostorbit.runtime.ipc import Client
from hostorbit.runtime.protocol import SHA256, ULID, canonical, checksum, decode, fields, integer, text
from hostorbit.runtime.storage import directory_sync, new_private_file, process_lock, protected_bytes


APP = Path("/opt/hostorbit")
CONFIG = Path("/etc/hostorbit")
UPDATE_STATE = Path("/var/lib/hostorbit/application-update")
COMPOSE_UNIT = "hostorbit-compose.service"
WEB_UNIT = "hostorbit-web.service"
SYSTEMCTL = "/usr/bin/systemctl"
BOOT_BLOCK = UPDATE_STATE / "service-start.blocked"
DROP_IN = Path("/etc/systemd/system") / (COMPOSE_UNIT + ".d") / "90-hostorbit-update-gate.conf"
OCI_REF = r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}"
APPLICATION_SERVICES = ("api", "worker")


def command(*args, timeout=60):
    result = subprocess.run(args, check=True, capture_output=True, timeout=timeout, text=True,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})
    return result.stdout.strip()


class ComposeServices:
    """Use the installed systemd unit and change only its pinned image references."""

    def __init__(self):
        installation = json.loads(protected_bytes(APP / "installation.json", owner=0, private=True))
        if (installation.get("v") != 1 or installation.get("project") != "hostorbit"
                or installation.get("docker_host") not in ("unix:///run/docker.sock", "unix:///var/run/docker.sock")):
            raise Denied("APPLICATION_INSTALLATION_INVALID")
        self.host = installation["docker_host"]
        self.path = CONFIG / "compose.json"
        self.web_active = (Path("/etc/systemd/system", WEB_UNIT).exists()
                           and command(SYSTEMCTL, "show", "-p", "ActiveState", "--value", WEB_UNIT) == "active")

    def docker(self, *args):
        return command("/usr/bin/docker", "--host", self.host, *args)

    def stage(self, images, digests):
        original = protected_bytes(self.path, owner=0, maximum=65536)
        updated = json.loads(original)
        if updated.get("name") != "hostorbit" or set(updated.get("services", ())) != set(APPLICATION_SERVICES):
            raise Denied("APPLICATION_COMPOSE_INVALID")
        for name in APPLICATION_SERVICES:
            image = text(images[name], OCI_REF, "APPLICATION_IMAGE_REFERENCE_INVALID")
            if image.split("@", 1)[1] != digests[name]:
                raise Denied("APPLICATION_IMAGE_DIGEST_MISMATCH")
            references = json.loads(self.docker("image", "inspect", "--format", "{{json .RepoDigests}}", image))
            if image not in references:
                raise Denied("APPLICATION_IMAGE_NOT_STAGED")
            updated["services"][name]["image"] = image
        return original, canonical(updated)

    def fence_start(self):
        document = f"[Unit]\nConditionPathExists=!{BOOT_BLOCK}\n".encode()
        DROP_IN.parent.mkdir(mode=0o755, exist_ok=True)
        info = DROP_IN.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Denied("APPLICATION_SYSTEMD_DIRECTORY_INVALID")
        if not os.path.lexists(DROP_IN):
            new_private_file(DROP_IN, document)
            directory_sync(DROP_IN.parent.parent)
        elif protected_bytes(DROP_IN, owner=0) != document:
            raise Denied("APPLICATION_SYSTEMD_FENCE_INVALID")
        command(SYSTEMCTL, "daemon-reload")
        marker = b"APPLICATION_UPDATE_PENDING\n"
        if not os.path.lexists(BOOT_BLOCK):
            new_private_file(BOOT_BLOCK, marker)
        elif protected_bytes(BOOT_BLOCK, owner=0, private=True) != marker:
            raise Denied("APPLICATION_SYSTEMD_FENCE_INVALID")

    def stop(self):
        command(SYSTEMCTL, "stop", COMPOSE_UNIT, timeout=90)
        running = self.docker("compose", "--project-name", "hostorbit", "--project-directory", str(APP),
                         "--file", str(self.path), "ps", "--status", "running", "-q")
        if running.strip():
            raise Denied("APPLICATION_WRITERS_STILL_RUNNING")

    def publish(self, document):
        atomic(self.path, document, mode=0o600)

    def start(self):
        # ExecStart runs compose up --wait using the unchanged service profiles.
        BOOT_BLOCK.unlink()
        directory_sync(BOOT_BLOCK.parent)
        command(SYSTEMCTL, "start", COMPOSE_UNIT, timeout=150)
        command(SYSTEMCTL, "is-active", "--quiet", COMPOSE_UNIT, timeout=10)
        if self.web_active:
            command(SYSTEMCTL, "start", WEB_UNIT, timeout=20)


def migrate_database(store, plan, deadline):
    before, after = plan["schema_before"], plan["schema_after"]
    if after not in (2, 3, 4) or after != before + 1:
        raise Denied("MIGRATION_SCHEMA_UNSUPPORTED")
    script, new_tables = migration_script(after)
    expected = plan["source_rows_sha256"]
    with store.write() as db:
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        _verify(db, before)
        sequence = db.execute("SELECT coalesce(max(seq),0) FROM audit").fetchone()[0]
        if not secrets.compare_digest(_source_digest(db, sequence, before)[0], expected):
            raise Denied("MIGRATION_REHEARSAL_SOURCE_CHANGED")
        for statement in _statements(script):
            db.execute(statement)
        Store.event(db, at=int(time.time()), actor="local-root", kind="database.schema_migrated", target="controller",
                    outcome="SUCCEEDED", correlation=plan["plan_id"],
                    details={"from_schema": before, "to_schema": after, "rehearsal": False,
                             "source_rows_sha256": expected, "plan_sha256": plan["plan_sha256"]})
        _verify(db, after)
        if (not secrets.compare_digest(_source_digest(db, sequence, before)[0], expected)
                or any(db.execute(f'SELECT 1 FROM "{name}" LIMIT 1').fetchone() for name in new_tables)):
            raise Denied("MIGRATION_PRESERVATION_FAILED")
        if time.monotonic() >= deadline:
            raise Denied("MIGRATION_APPLY_TIMEOUT")


def apply_update(config, release, release_key, gate, approval, images, services, directory, *, inputs, owner=0):
    if os.geteuid() != owner:
        raise Denied("LOCAL_ROOT_REQUIRED")
    fields(approval, ("plan_id", "revision", "approval_id", "plan_sha256"))
    text(approval["plan_id"], ULID)
    integer(approval["revision"], 1, 2**31 - 1)
    text(approval["approval_id"], ULID)
    text(approval["plan_sha256"], SHA256)
    fields(images, APPLICATION_SERVICES)
    directory = Path(directory).absolute()
    private_slots(directory)
    pending = directory / "pending.json"

    def review(**options):
        return prepare_migration(config, release, release_key, gate, **inputs, owner=owner, **options)

    with process_lock(directory / "update.lock"):
        if os.path.lexists(pending):
            raise Denied("APPLICATION_UPDATE_RECOVERY_REQUIRED")
        prepared = review()
        plan = prepared["plan"]
        attestation = prepared["owner_restore_attestation"]
        if not attestation or attestation["status"] != "OWNER_RESTORE_ATTESTATION_VERIFIED":
            raise Denied("APPLICATION_RESTORE_ATTESTATION_REQUIRED")
        digest = prepared["plan_sha256"]
        if not secrets.compare_digest(digest, approval["plan_sha256"]):
            raise Denied("APPLICATION_APPROVAL_MISMATCH")
        release_args = {name: inputs[name] for name in ("installed", "bootstrap", "schema", "vault_format", "minimum_release")}
        candidate = verify_candidate(release, release_key, **release_args)
        if candidate["release_sha256"] != plan["release_sha256"]:
            raise Denied("APPLICATION_RELEASE_CHANGED")
        original, updated = services.stage(images, candidate["images"])

        identity = {name: approval[name] for name in ("plan_id", "revision")}
        request = {**identity, "kind": "application", "plan_digest": digest, "approval_id": approval["approval_id"],
                   "time_anchor": gate.call("time.anchor", identity)}
        progress = {"v": 1, "phase": "QUIESCING", "plan": plan, "approval": approval, "images": images}
        new_private_file(pending, canonical(progress))

        def phase(value):
            progress["phase"] = value
            atomic(pending, canonical(progress))

        ticket = enter_maintenance(gate, request)
        if ticket["epoch"] != plan["gate_epoch"] + 1:
            raise Denied("APPLICATION_UPDATE_GATE_CHANGED")
        phase("STOPPING")
        services.fence_start()
        services.stop()
        phase("SERVICES_STOPPED")
        committed = False
        store = Store(config["database"], access=DataAccess(config["app_uid"], config.get("app_gid")))
        try:
            latest = review(gate_state="MAINTENANCE")["plan"]
            if latest["gate_epoch"] != ticket["epoch"] or checksum({**latest, "gate_epoch": plan["gate_epoch"]}) != digest:
                raise Denied("APPLICATION_UPDATE_PLAN_CHANGED")
            admission = Admission(config["writer_directory"], owner=owner)
            with admission.exclusive(timeout=20):
                phase("MIGRATING")
                migrate_database(store, {**plan, "plan_id": identity["plan_id"], "plan_sha256": digest},
                                 time.monotonic() + 20)
                committed = True
                phase("SCHEMA_COMMITTED")
        except Exception:
            # A failed or uncertain SQLite COMMIT must be resolved from the
            # durable schema before restarting the previous application.
            with store.connect(readonly=True) as db:
                schema = db.execute("PRAGMA user_version").fetchone()[0]
            if not committed and schema == plan["schema_before"]:
                services.publish(original)
                services.start()
                phase("PREVIOUS_SERVICES_RESTORED")
            raise

        services.publish(updated)
        phase("STARTING_NEW_SERVICES")
        try:
            services.start()
            check_gate(gate, "update.resuming", ticket, "RESUMING")
            check_gate(gate, "update.normal", ticket, "NORMAL")
        except Exception:
            services.fence_start()
            services.stop()
            # The committed DB may have new writes. Never restore an old DB
            # or start binaries expecting the old schema in this state.
            raise
        pending.unlink()
        directory_sync(directory)
        return {"status": "APPLICATION_UPDATED", "version": plan["release_version"],
                "schema": plan["schema_after"], "plan_sha256": digest}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    for name in ("trust-key", "approval", "review", "downloaded-copy", "restore-attestation", "restore-evidence", "owner-verify-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("installed", "bootstrap", "minimum-release", "snapshot-id", "api-image", "worker-image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--schema", type=int, required=True)
    parser.add_argument("--vault-format", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Denied("LOCAL_ROOT_REQUIRED")
        config = configuration(CONFIG / "runtime.json")
        inputs = {name: getattr(args, name) for name in ("installed", "bootstrap", "schema", "vault_format",
                                                        "minimum_release", "review", "snapshot_id", "downloaded_copy")}
        inputs["restore"] = {"record": protected_bytes(args.restore_attestation, owner=0, private=True),
                             "evidence": protected_bytes(args.restore_evidence, owner=0, private=True, maximum=MAX_EVIDENCE),
                             "owner_key": trusted_key(args.owner_verify_key)}
        approval = decode(protected_bytes(args.approval, owner=0, private=True), canonical_required=False)
        result = apply_update(config, args.release, trusted_key(args.trust_key), Client(config["gate_socket"], server_uids={0}),
                              approval, {"api": args.api_image, "worker": args.worker_image}, ComposeServices(),
                              UPDATE_STATE, inputs=inputs)
    except (Denied, ArtifactError, OSError, RuntimeError, ValueError, sqlite3.Error, KeyError, TypeError, subprocess.SubprocessError) as error:
        code = error.code if isinstance(error, Denied) else str(error) if isinstance(error, ArtifactError) else "APPLICATION_UPDATE_UNAVAILABLE"
        print(f"HostOrbit: {code}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
