"""Select a signed host-updater package under the local Supervisor gate."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import tempfile

from deploy.artifact import ArtifactError, trusted_key
from deploy.rehearse_update import select_slot, stage_candidate
from deploy.update_release import verify_candidate
from hostorbit.errors import Denied
from hostorbit.runtime.cli import configuration
from hostorbit.runtime.ipc import Client
from hostorbit.runtime.protocol import SHA256, ULID, canonical, decode, fields, integer, text
from hostorbit.runtime.storage import directory_sync, new_private_file, process_lock, protected_bytes


def private_slots(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise Denied("UPDATE_DIRECTORY_UNTRUSTED")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise Denied("UPDATE_DIRECTORY_UNTRUSTED")
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Denied("UPDATE_DIRECTORY_UNTRUSTED")
    directory_sync(path.parent)


def approval_fields(approval):
    fields(approval, ("plan_id", "revision", "approval_id", "release_sha256"))
    text(approval["plan_id"], ULID)
    integer(approval["revision"], 1, 2**31 - 1)
    text(approval["approval_id"], ULID)
    text(approval["release_sha256"], SHA256)


def slot_name(root):
    link = root / "active"
    if not os.path.lexists(link):
        return None
    if not link.is_symlink():
        raise Denied("UPDATE_ACTIVE_SLOT_INVALID")
    value = os.readlink(link)
    if value not in ("A", "B"):
        raise Denied("UPDATE_ACTIVE_SLOT_INVALID")
    return value


def check_gate(gate, operation, ticket, state):
    actual = gate.call(operation, ticket)
    if actual != {"state": state, "epoch": ticket["epoch"]}:
        raise Denied("UPDATE_GATE_RESPONSE_INVALID")


def select_update(source, root, key, gate, approval, *, installed, bootstrap, schema, vault_format, minimum_release):
    approval_fields(approval)
    root = Path(root).absolute()
    private_slots(root)
    with process_lock(root / "update.lock"):
        pending = root / "pending.json"
        if os.path.lexists(pending):
            raise Denied("UPDATE_RECOVERY_REQUIRED")
        previous = slot_name(root)
        compatibility = dict(installed=installed, bootstrap=bootstrap, schema=schema, vault_format=vault_format,
                             minimum_release=minimum_release)
        if previous is not None:
            baseline = verify_candidate(root / previous, key, **{**compatibility, "installed": "0.0.0",
                                                                "minimum_release": "0.0.0"})
            if baseline["version"] != installed or baseline["schema_to"] != schema:
                raise Denied("UPDATE_BASELINE_CHANGED")
        target = "A" if previous != "A" else "B"
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=root) as directory:
            staged = Path(directory) / "package"
            candidate = stage_candidate(Path(source), staged, key, compatibility)
            if candidate["schema_to"] != schema:
                raise Denied("UPDATE_SCHEMA_CHANGE_BLOCKED")
            if not secrets.compare_digest(candidate["release_sha256"], approval["release_sha256"]):
                raise Denied("UPDATE_APPROVAL_MISMATCH")
            for path in staged.iterdir():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            directory_sync(staged)

            identity = {name: approval[name] for name in ("plan_id", "revision")}
            request = {**identity, "kind": "self", "plan_digest": candidate["release_sha256"],
                       "approval_id": approval["approval_id"], "time_anchor": gate.call("time.anchor", identity)}
            new_private_file(pending, canonical({"v": 1, "previous_slot": previous, "candidate_slot": target,
                                                "release_sha256": candidate["release_sha256"], **identity}))
            ticket = gate.call("update.quiesce", request)
            fields(ticket, (*request, "epoch", "nonce"))
            integer(ticket["epoch"], 1, 2**63 - 1)
            text(ticket["nonce"], SHA256)
            if any(ticket[field] != value for field, value in request.items()):
                raise Denied("UPDATE_GATE_RESPONSE_INVALID")
            check_gate(gate, "update.maintenance", ticket, "MAINTENANCE")

            destination = root / target
            if os.path.lexists(destination):
                if not stat.S_ISDIR(destination.lstat().st_mode):
                    raise Denied("UPDATE_INACTIVE_SLOT_INVALID")
                shutil.rmtree(destination)
            staged.rename(destination)
            directory_sync(root)
            try:
                select_slot(root, target)
                if verify_candidate(destination, key, **compatibility) != candidate:
                    raise Denied("UPDATE_PACKAGE_CHECK_FAILED")
                check_gate(gate, "update.resuming", ticket, "RESUMING")
                check_gate(gate, "update.normal", ticket, "NORMAL")
            except BaseException:
                if slot_name(root) == target:
                    if previous is None:
                        (root / "active").unlink()
                        directory_sync(root)
                    else:
                        select_slot(root, previous)
                raise
            pending.unlink()
            directory_sync(root)
        return {"status": "UPDATER_PACKAGE_SELECTED", "slot": target, "version": candidate["version"],
                "release_sha256": candidate["release_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--installed", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--minimum-release", required=True)
    parser.add_argument("--schema", type=int, required=True)
    parser.add_argument("--vault-format", type=int, required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("HostOrbit: LOCAL_ROOT_REQUIRED", file=sys.stderr)
        return 1
    try:
        config = configuration(Path("/etc/hostorbit/runtime.json"))
        gate = Client(config["gate_socket"], server_uids={0})
        report = select_update(args.directory, Path("/var/lib/hostorbit/update-slots"), trusted_key(args.trust_key),
                               gate, decode(protected_bytes(args.approval, owner=0, private=True), canonical_required=False),
                               installed=args.installed, bootstrap=args.bootstrap, minimum_release=args.minimum_release,
                               schema=args.schema, vault_format=args.vault_format)
    except (ArtifactError, Denied, OSError, ValueError) as error:
        if isinstance(error, ArtifactError):
            code = str(error)
        elif isinstance(error, Denied):
            code = error.code
        else:
            code = "UPDATE_UNAVAILABLE"
        print(f"HostOrbit: {code}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
