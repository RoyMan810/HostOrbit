"""AC-A02 lab. Recover on a fresh guest after destroying the source guest's disk."""

import argparse
import base64
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
import hashlib
from io import BufferedRWPair
import json
import os
from pathlib import Path
from platform import freedesktop_os_release
import secrets
import shutil
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import traceback

from nacl.secret import Aead
from nacl.signing import SigningKey, VerifyKey

import fencing_vm as fencing
from sftp_publication import SftpFailure, SftpPublication, age_key, command, listen, restored_values, sftp_receiver
from stage0.admission import HostGate
from stage0.recovery import RecoveryRequest, Rejected, SignedBackup, Snapshot, accept_bundle, issue_request, prepare_bundle, seal_source
from stage0.snapshot import BackupLab, Work


_DEVICE = "/dev/virtio-ports/hostorbit.recovery"
_SFTP_HOST = "10.0.2.100"
_SFTP_PORT = 2222
_VALUES = {"old": b"retained-generation", "current": b"active-generation"}
_LIMIT = 12 * 1024 * 1024


def b64(data):
    return base64.b64encode(data).decode("ascii")


def decode(data):
    return base64.b64decode(data, validate=True)


def receive(stream):
    line = stream.readline(_LIMIT + 1)
    if not line.endswith(b"\n") or len(line) > _LIMIT:
        raise RuntimeError("Missing or oversized fixture message")
    message = json.loads(line)
    if "guest_error" in message:
        raise RuntimeError(f"Guest fixture failed ({message['guest_error']})")
    return message


def send(stream, message):
    stream.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")
    stream.flush()


def receive_attestation(stream):
    proof = receive(stream)
    digest = receive(stream)["digest"]
    fencing.wait_for_observation_time(proof["observed_at"])
    return decode(proof["record"]), decode(proof["signature"]), digest


def send_attestation(stream, binding, attester, managed, new_key, off_at, *, delegated_terminal):
    record, signature, digest, observed_at = fencing.attestation(
        binding, attester, managed, new_key, off_at, delegated_terminal=delegated_terminal,
    )
    send(stream, {"record": b64(record), "signature": b64(signature), "observed_at": observed_at})
    send(stream, {"digest": digest})


def wrapped_only(lab, backup_id):
    # The original Vault pins are still held during publication.
    capture = lab._capture(backup_id, time.monotonic() + 10)
    vault = {
        "keys": {version: b64(capture.wrapped[ref]) for version, ref in capture.generations.items()},
        "ciphertexts": {ref: b64(data) for ref, data in capture.ciphertexts.items()},
    }
    return Snapshot(capture.database, json.dumps(vault).encode("ascii"))


def publish_source(root, endpoint, signer, recipient):
    controller = root / "controller"
    controller.mkdir(mode=0o700)
    wrap_path = controller / "os-wrap.key"
    wrap_path.write_bytes(secrets.token_bytes(Aead.KEY_SIZE))
    (controller / "controller-signing.key").write_bytes(bytes(signer))
    lab = BackupLab.create(controller, wrap_path.read_bytes())
    for name, value in _VALUES.items():
        lab.finish_rotation(lab.admit(Work.ROTATION), name, value)
    wrapped_id = secrets.token_hex(16)

    def publish(backup_id, backup):
        receipt = endpoint.publish(backup_id, backup)
        invalid = seal_source(wrapped_only(lab, backup_id), recipient, signer)
        endpoint.publish(wrapped_id, invalid)
        return receipt

    return {"portable": lab.run(recipient, signer, publish), "os_wrapped": wrapped_id}


def recover_guest(stream, root, endpoint, archives):
    for name in ("portable", "os_wrapped"):
        archive = endpoint.fetch(archives[name])
        if name == "portable":
            try:
                endpoint.publish(secrets.token_hex(16), archive)
            except SftpFailure as error:
                if error.phase != "upload" or "Permission denied" not in str(error):
                    raise
            else:
                raise RuntimeError("The recovery SFTP key allowed a write")
        identity = root / f"{name}.agekey"
        age_key(identity)
        ledger = root / f"{name}.sqlite3"
        request = issue_request(
            ledger, target_id="offhost-fresh-guest", transport_identity=identity,
            source_envelope_sha256=archive.envelope_sha256,
        )
        send(stream, {"request": asdict(request), "archive": [b64(data) for data in (
            archive.ciphertext, archive.envelope, archive.signature,
        )]})
        bundle = decode(receive(stream)["bundle"])
        snapshot = accept_bundle(ledger, identity, bundle, owner_digest=receive(stream)["owner_digest"])
        identity.unlink()
        if name == "portable":
            values, versions = restored_values(snapshot)
            if values != _VALUES or versions != [1, 2]:
                raise RuntimeError("The recovered secret values or DEK versions differ")
            (root / "controller.sqlite3").write_bytes(snapshot.database)
            send(stream, {"sqlite": "ok", "versions": versions})
        else:
            try:
                restored_values(snapshot)
            except Rejected as error:
                if str(error) != "PORTABLE_DEK_REQUIRED":
                    raise
            else:
                raise RuntimeError("The OS-wrapped-only archive was accepted")
            send(stream, {"rejected": "PORTABLE_DEK_REQUIRED"})


def guest(stream):
    root = Path("/var/lib/hostorbit-offhost")
    root.mkdir(mode=0o700)
    ssh_identity = root / "sftp-client"
    command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ssh_identity)
    send(stream, {"ready": True})
    boot = receive(stream)
    role = boot["role"]
    signer = SigningKey.generate() if role == "source" else None
    greeting = {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "sftp_key": ssh_identity.with_suffix(".pub").read_text(encoding="ascii"),
        "signing_key": b64(bytes(signer.verify_key)) if signer is not None else None,
    }
    managed_identity = root / "managed-client"
    if boot["managed"] and role == "source":
        host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text(encoding="ascii")
        greeting["old_host_key_sha256"] = fencing.key_fingerprint(host_key)
    elif boot["managed"]:
        command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", managed_identity)
        greeting["managed_key"] = managed_identity.with_suffix(".pub").read_text(encoding="ascii")
    send(stream, greeting)
    config = receive(stream)
    known_hosts = root / "known_hosts"
    known_hosts.write_text(f"[{_SFTP_HOST}]:{_SFTP_PORT} {config['host_key']}\n", encoding="ascii")
    endpoint = SftpPublication(config["account"], _SFTP_PORT, ssh_identity, known_hosts, host=_SFTP_HOST)
    if role == "source":
        if boot["managed"]:
            managed_identity.write_bytes(decode(config["old_managed_identity"]))
            pinned = fencing.guest_known_hosts(root, config["managed_host_key"])
            send(stream, {"old_invocation": fencing.source_restart(root, managed_identity, pinned)})
        send(stream, publish_source(root, endpoint, signer, config["recipient"]))
        if boot["deferred"]:
            outcome = fencing.restart_docker(HostGate(root / "source-gate.sqlite3"), managed_identity, pinned)
            send(stream, {"old_outcome": outcome})
    elif role == "recovery":
        recover_guest(stream, root, endpoint, config["archives"])
        if boot["managed"]:
            pinned = fencing.guest_known_hosts(root, config["managed_host_key"])
            target = receive(stream)["binding"]
            target["owner_verify_key"] = decode(target["owner_verify_key"])
            gate = fencing.recovery_gate(root, managed_identity, pinned, target)
            send(stream, {"blocked": "READ_ONLY_RECOVERY", "unreachable": True})
            if boot["deferred"]:
                record, signature, digest = receive_attestation(stream)
                fencing.expect_denial(
                    "NO_SAFE_RECOVERY_TARGETS", gate.activate_recovery, record, signature, owner_confirmation=digest,
                )
                gate = HostGate(root / "recovery-gate.sqlite3")
                fencing.expect_denial("READ_ONLY_RECOVERY", fencing.restart_docker, gate, managed_identity, pinned)
                send(stream, {"pending_blocked": True})
            record, signature, digest = receive_attestation(stream)
            if boot["deferred"]:
                fencing.expect_denial("READ_ONLY_RECOVERY", fencing.restart_docker, gate, managed_identity, pinned)
            safe = gate.activate_recovery(record, signature, owner_confirmation=digest)
            if safe != {"managed"}:
                raise RuntimeError("Unexpected activation scope")
            fencing.expect_denial("QUARANTINED", fencing.restart, gate, managed_identity, pinned, "unavailable")
            send(stream, {"new_invocation": fencing.restart(gate, managed_identity, pinned)})
    else:
        raise ValueError("Unknown fixture guest role")


def offline_owner(identity):
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("Owner preparation must run in a network namespace")
    transfer = receive(sys.stdin.buffer)
    request = RecoveryRequest(**transfer["request"])
    archive = SignedBackup(*(decode(part) for part in transfer["archive"]))
    signer = VerifyKey(decode(transfer["signing_key"]))
    bundle, review = prepare_bundle(archive, signer, identity, request)
    manifest = json.dumps(review.manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    send(sys.stdout.buffer, {
        "bundle": b64(bundle), "owner_digest": review.bundle_sha256,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    })


def make_seed(work, dependencies, age_dir):
    payload = work / "payload"
    payload.mkdir()
    repo = Path(__file__).resolve().parents[2]
    shutil.copytree(repo / "stage0", payload / "stage0", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(dependencies, payload / "deps", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("offhost_recovery.py", "sftp_publication.py", "fencing_vm.py", "ssh_restart_fixture.py"):
        shutil.copyfile(Path(__file__).with_name(name), payload / name)
    for name in ("age", "age-keygen"):
        shutil.copy2(age_dir / name, payload / name)
    (payload / "meta-data").write_text("instance-id: hostorbit-offhost\n", encoding="ascii")
    (payload / "user-data").write_text("""#cloud-config
users: []
ssh_pwauth: false
growpart:
  mode: "off"
resize_rootfs: false
runcmd:
  - [mkdir, -p, /mnt/hostorbit]
  - [mount, -o, ro, "LABEL=cidata", /mnt/hostorbit]
  - [modprobe, virtio_console]
  - [udevadm, settle, "--timeout=15"]
  - [env, "PYTHONPATH=/mnt/hostorbit:/mnt/hostorbit/deps", "PATH=/mnt/hostorbit:/usr/bin:/bin", /usr/bin/python3, /mnt/hostorbit/offhost_recovery.py, --guest]
""", encoding="ascii")
    seed = work / "seed.iso"
    command("/usr/bin/xorriso", "-as", "mkisofs", "-quiet", "-r", "-V", "cidata", "-o", seed, payload)
    return seed


def connect_guest(path, process):
    stream = socket.socket(socket.AF_UNIX)
    try:
        deadline = time.monotonic() + 20
        while process.poll() is None and time.monotonic() < deadline:
            try:
                stream.connect(str(path))
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.1)
                continue
            stream.settimeout(240)
            return stream
        raise RuntimeError("QEMU did not open its fixture console")
    except BaseException:
        stream.close()
        raise


@contextmanager
def boot_guest(work, console, role, image, seed, sftp_port, managed):
    disk = work / f"{role}.qcow2"
    command("/usr/bin/qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, disk)
    port = console / f"{role}.sock"
    serial = work / f"{role}-serial.log"
    log = work / f"{role}-qemu.log"
    ports = {_SFTP_PORT: sftp_port}
    if managed is not None:
        ports[fencing.MANAGED_PORT] = managed.port
    forwarding = ",".join(
        f"guestfwd=tcp:{_SFTP_HOST}:{guest_port}-cmd:/usr/bin/nc 127.0.0.1 {host_port}"
        for guest_port, host_port in ports.items()
    )
    with log.open("wb") as errors:
        process = subprocess.Popen([
            "/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "max",
            "-smp", "2", "-m", "1536", "-display", "none", "-monitor", "none", "-no-reboot",
            "-serial", f"file:{serial}",
            "-drive", f"if=virtio,format=qcow2,file={disk}",
            "-drive", f"if=virtio,format=raw,readonly=on,file={seed}",
            "-netdev", f"user,id=network,restrict=on,ipv6=off,{forwarding}",
            "-device", "virtio-net-pci,netdev=network",
            "-chardev", f"socket,id=control,path={port},server=on,wait=off",
            "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=control,name=hostorbit.recovery",
        ], stdin=subprocess.DEVNULL, stdout=errors, stderr=errors)
        try:
            with connect_guest(port, process) as channel, channel.makefile("rwb") as stream:
                if receive(stream) != {"ready": True}:
                    raise RuntimeError("Unexpected fixture console greeting")
                send(stream, {
                    "role": role, "managed": managed is not None,
                    "deferred": managed is not None and managed.deferred is not None,
                })
                yield stream
        except Exception:
            for path in (log, serial):
                if path.exists():
                    print(path.read_text(encoding="utf-8", errors="replace")[-8000:], file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            disk.unlink()


def experiment(work, console, image, dependencies, age_dir, managed):
    seed = make_seed(work, dependencies, age_dir)
    owner = work / "offline-owner.agekey"
    recipient = age_key(owner)
    store_root = console / "receiver"
    store_root.mkdir()
    with sftp_receiver(store_root) as receiver, listen(receiver.config, work / "sftp.log") as port:
        settings = {"account": receiver.account, "host_key": receiver.host_key}
        deferred = managed.deferred if managed is not None else None
        if managed is not None:
            original_invocation = fencing.invocation(managed.unit)
            settings["managed_host_key"] = managed.host_key
        with boot_guest(work, console, "source", image, seed, port, managed) as stream:
            source = receive(stream)
            receiver.authorize(source["sftp_key"])
            source_config = {**settings, "recipient": recipient}
            if managed is not None:
                source_config["old_managed_identity"] = b64((managed.lab / "client").read_bytes())
            send(stream, source_config)
            if managed is not None:
                old_invocation = receive(stream)["old_invocation"]
                if old_invocation == original_invocation or old_invocation != fencing.invocation(managed.unit):
                    raise RuntimeError("The original Controller did not restart the managed service")
            archives = receive(stream)
            if set(archives) != {"portable", "os_wrapped"} or set(archives.values()) != {p.name for p in receiver.store.iterdir()}:
                raise RuntimeError("The SFTP store is missing a completed fixture archive")
            print("Source VM published the portable and OS-wrapped-only archives over SFTP.", flush=True)
            if deferred is not None:
                deferred.stop_direct_client()
                if receive(stream) != {"old_outcome": "UNKNOWN_OUTCOME"}:
                    raise RuntimeError("The source did not preserve an unknown Docker outcome after SSH loss")
                print("SSH and the direct cgroup stopped while the Docker effect remained pending.", flush=True)
        if (work / "source.qcow2").exists():
            raise RuntimeError("The source system disk still exists")
        off_at = int(time.time())
        print("Source VM stopped and its writable system disk and credential store were removed.", flush=True)
        if deferred is not None:
            deferred.require_pending()

        with boot_guest(work, console, "recovery", image, seed, port, managed) as stream:
            target = receive(stream)
            if target["boot_id"] == source["boot_id"] or target["sftp_key"].split()[1] == source["sftp_key"].split()[1]:
                raise RuntimeError("Recovery VM reused source identity")
            receiver.authorize(target["sftp_key"], read_only=True)
            if managed is not None:
                managed.rotate(target["managed_key"])
                print("The managed SSH server denied the retired key after the source VM was powered off.", flush=True)
            send(stream, {**settings, "archives": archives})
            results = ({"sqlite": "ok", "versions": [1, 2]}, {"rejected": "PORTABLE_DEK_REQUIRED"})
            for expected in results:
                transfer = receive(stream)
                transfer["signing_key"] = source["signing_key"]
                reviewed = subprocess.run(
                    ["/usr/bin/unshare", "--net", sys.executable, __file__, "--offline-owner", owner],
                    input=json.dumps(transfer).encode("ascii") + b"\n", capture_output=True, timeout=30,
                )
                if reviewed.returncode:
                    raise RuntimeError(f"Offline Owner preparation failed: {reviewed.stderr.decode('utf-8', 'replace')}")
                package = json.loads(reviewed.stdout)
                send(stream, {"bundle": package["bundle"]})
                send(stream, {"owner_digest": package["owner_digest"]})
                if receive(stream) != expected:
                    raise RuntimeError("Unexpected restore result")
                if expected == results[0]:
                    manifest_sha256 = package["manifest_sha256"]
            if managed is not None:
                attester = SigningKey.generate()
                binding = {
                    "old_controller_id": source["boot_id"], "old_host_key_sha256": source["old_host_key_sha256"],
                    "recovery_controller_id": target["boot_id"], "backup_manifest_sha256": manifest_sha256,
                    "owner_verify_key": bytes(attester.verify_key),
                }
                send(stream, {"binding": {**binding, "owner_verify_key": b64(binding["owner_verify_key"])}})
                if receive(stream) != {"blocked": "READ_ONLY_RECOVERY", "unreachable": True}:
                    raise RuntimeError("Expected the recovered Controller to stay read-only before activation")
                if fencing.invocation(managed.unit) != old_invocation or (work / "source.qcow2").exists():
                    raise RuntimeError("Read-only recovery changed the service or the source disk reappeared")
                print("The fresh VM had a valid key but the read-only gate prevented a restart.", flush=True)
                if deferred is not None:
                    deferred.require_pending()
                    send_attestation(stream, binding, attester, managed, target["managed_key"], off_at,
                                     delegated_terminal=False)
                    if receive(stream) != {"pending_blocked": True} or fencing.invocation(managed.unit) != old_invocation:
                        raise RuntimeError("The recovered Controller did not keep the unresolved host read-only")
                    print("The recovered Controller refused activation and a second Docker restart while the effect was pending.", flush=True)
                    deferred.release_and_verify()
                send_attestation(stream, binding, attester, managed, target["managed_key"], off_at,
                                 delegated_terminal=True)
                restarted = receive(stream)["new_invocation"]
                if restarted == old_invocation or restarted != fencing.invocation(managed.unit):
                    raise RuntimeError("The activated Controller did not restart the verified service")
                print("The activated Controller restarted the verified service. The unreachable host remained quarantined.", flush=True)
    print("Fresh VM verified SQLite and DEK generations 1 and 2. OS-wrapped-only restore was rejected.", flush=True)


def main():
    os.umask(0o077)
    if sys.argv[1:] == ["--guest"]:
        with open(_DEVICE, "r+b", buffering=0) as port, BufferedRWPair(port, port) as stream:
            try:
                guest(stream)
            except Exception as error:
                traceback.print_exc()
                reason = str(error) if isinstance(error, Rejected) else type(error).__name__
                send(stream, {"guest_error": reason})
                raise SystemExit(1) from None
        return
    if sys.argv[1:2] == ["--offline-owner"] and len(sys.argv) == 3:
        offline_owner(Path(sys.argv[2]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--age-dir", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--ssh-fixture", nargs=4, metavar=("LAB", "PORT", "HELPERS", "AUTHORIZED"))
    args = parser.parse_args()
    release = freedesktop_os_release()
    if os.geteuid() != 0 or (release["ID"], release["VERSION_ID"]) != ("ubuntu", "24.04"):
        raise SystemExit("Run as root in a disposable Ubuntu 24.04 VM.")
    service = nullcontext()
    if args.ssh_fixture is not None:
        lab, port, helper_dir, authorized = args.ssh_fixture
        service = fencing.managed_service(
            Path(lab), int(port), Path(helper_dir), Path(authorized), os.environ.get("HOSTORBIT_LAB_PYTHON_IMAGE"),
        )
    with service as managed, TemporaryDirectory(prefix="hostorbit-guests-", dir=args.scratch) as work, \
            TemporaryDirectory(prefix="hostorbit-console-", dir="/run") as console:
        Path(console).chmod(0o711)
        experiment(Path(work), Path(console), args.image.resolve(), args.dependencies, args.age_dir, managed)


if __name__ == "__main__":
    main()
