"""Authenticated local activation console, never a Web or Worker endpoint."""

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from ..errors import Denied
from .activation import Activation
from .archive_stream import parse_manifest
from .cli import configuration
from .coordinator import _Expired
from .protocol import canonical, text, unique_object
from .policy import Policy
from .recovery_install import _record, _key
from .rescue import harden
from .rescue_cli import console
from .storage import protected_bytes


def installed_binding(config, state, old_host_key):
    text(old_host_key, r"SHA256:[A-Za-z0-9+/]{43}", "ACTIVATION_SOURCE_HOST_KEY_REQUIRED")
    state, source, request, row, receipt, claims, policy = _record(state, installed=True)
    complete = parse_manifest(protected_bytes(state / "installation.complete.json", owner=0, exact_mode=0o600))
    installed = parse_manifest(protected_bytes(Path(config["supervisor_directory"]) / "recovery-installation.json", owner=0, exact_mode=0o600))
    if (complete != installed or complete["target_id"] != request["target_id"] or complete["bundle_sha256"] != receipt["bundle_sha256"]
            or policy.digest != Policy.load(config["targets"]).digest):
        raise Denied("ACTIVATION_INSTALLATION_BINDING_INVALID")
    with _key(source):
        pass
    return {"target_id": request["target_id"], "source_instance": receipt["source_instance"],
            "source_backup_hash": receipt["source_backup_hash"], "bundle_sha256": receipt["bundle_sha256"],
            "artifact_sha256": complete["artifact_sha256"], "old_host_key": old_host_key}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hostorbit-activate")
    parser.add_argument("--config", type=Path, default=Path("/etc/hostorbit/runtime.json"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--old-host-key", required=True, help="Independently saved source Controller public SSH fingerprint")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--report", type=Path, required=True)
    prepare.add_argument("--policy", type=Path, required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--plan-id", required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Denied("LOCAL_ROOT_REQUIRED")
        harden()
        console()
        config = configuration(args.config)
        binding = installed_binding(config, args.state, args.old_host_key)
        manager = Activation(config, binding)
        if args.command == "prepare":
            report = json.loads(protected_bytes(args.report, owner=0, maximum=65536, private=True), object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite report")))
            result = manager.prepare(report, Policy.load(args.policy))
        else:
            digest = input("Exact confirmation SHA-256 from the reviewed activation plan: ").strip()
            username = input("Owner username: ").strip()
            password = getpass.getpass("Owner password: ")
            try:
                result = manager.activate(args.plan_id, digest, username, password)
            finally:
                del password
        print(canonical(result).decode())
        return 0
    except _Expired:
        print("ACTIVATION_BARRIER_TIMEOUT", file=sys.stderr)
        return 2
    except Exception as error:
        print(error.code if isinstance(error, Denied) else "ACTIVATION_UNAVAILABLE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
