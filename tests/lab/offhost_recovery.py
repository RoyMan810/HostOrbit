"""AC-A02 lab. Recover on a fresh guest after destroying the source guest's disk."""

import argparse
import base64
from contextlib import contextmanager
from dataclasses import asdict
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

from nacl.secret import Aead
from nacl.signing import SigningKey, VerifyKey

from sftp_publication import SftpFailure, SftpPublication, age_key, command, listen, restored_values, sftp_receiver
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
    return json.loads(line)


def send(stream, message):
    stream.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")
    stream.flush()


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


def guest():
    root = Path("/var/lib/hostorbit-offhost")
    root.mkdir(mode=0o700)
    ssh_identity = root / "sftp-client"
    command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ssh_identity)
    with open(_DEVICE, "r+b", buffering=0) as port, BufferedRWPair(port, port) as stream:
        send(stream, {"ready": True})
        role = receive(stream)["role"]
        signer = SigningKey.generate() if role == "source" else None
        send(stream, {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "sftp_key": ssh_identity.with_suffix(".pub").read_text(encoding="ascii"),
            "signing_key": b64(bytes(signer.verify_key)) if signer is not None else None,
        })
        config = receive(stream)
        known_hosts = root / "known_hosts"
        known_hosts.write_text(f"[{_SFTP_HOST}]:{_SFTP_PORT} {config['host_key']}\n", encoding="ascii")
        endpoint = SftpPublication(config["account"], _SFTP_PORT, ssh_identity, known_hosts, host=_SFTP_HOST)
        if role == "source":
            send(stream, publish_source(root, endpoint, signer, config["recipient"]))
        elif role == "recovery":
            recover_guest(stream, root, endpoint, config["archives"])
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
    send(sys.stdout.buffer, {"bundle": b64(bundle), "owner_digest": review.bundle_sha256})


def make_seed(work, dependencies, age_dir):
    payload = work / "payload"
    payload.mkdir()
    repo = Path(__file__).resolve().parents[2]
    shutil.copytree(repo / "stage0", payload / "stage0", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(dependencies, payload / "deps", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("offhost_recovery.py", "sftp_publication.py"):
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
def boot_guest(work, console, role, image, seed, sftp_port):
    disk = work / f"{role}.qcow2"
    command("/usr/bin/qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, disk)
    port = console / f"{role}.sock"
    serial = work / f"{role}-serial.log"
    log = work / f"{role}-qemu.log"
    with log.open("wb") as errors:
        process = subprocess.Popen([
            "/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "max",
            "-smp", "2", "-m", "1536", "-display", "none", "-monitor", "none", "-no-reboot",
            "-serial", f"file:{serial}",
            "-drive", f"if=virtio,format=qcow2,file={disk}",
            "-drive", f"if=virtio,format=raw,readonly=on,file={seed}",
            "-netdev", f"user,id=network,restrict=on,ipv6=off,guestfwd=tcp:{_SFTP_HOST}:{_SFTP_PORT}-cmd:/usr/bin/nc 127.0.0.1 {sftp_port}",
            "-device", "virtio-net-pci,netdev=network",
            "-chardev", f"socket,id=control,path={port},server=on,wait=off",
            "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=control,name=hostorbit.recovery",
        ], stdin=subprocess.DEVNULL, stdout=errors, stderr=errors)
        try:
            with connect_guest(port, process) as channel, channel.makefile("rwb") as stream:
                if receive(stream) != {"ready": True}:
                    raise RuntimeError("Unexpected fixture console greeting")
                send(stream, {"role": role})
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


def experiment(work, console, image, dependencies, age_dir):
    seed = make_seed(work, dependencies, age_dir)
    owner = work / "offline-owner.agekey"
    recipient = age_key(owner)
    store_root = console / "receiver"
    store_root.mkdir()
    with sftp_receiver(store_root) as receiver, listen(receiver.config, work / "sftp.log") as port:
        settings = {"account": receiver.account, "host_key": receiver.host_key}
        with boot_guest(work, console, "source", image, seed, port) as stream:
            source = receive(stream)
            receiver.authorize(source["sftp_key"])
            send(stream, {**settings, "recipient": recipient})
            archives = receive(stream)
            if set(archives) != {"portable", "os_wrapped"} or set(archives.values()) != {p.name for p in receiver.store.iterdir()}:
                raise RuntimeError("The SFTP store is missing a completed fixture archive")
            print("Source VM published the portable and OS-wrapped-only archives over SFTP.", flush=True)
        if (work / "source.qcow2").exists():
            raise RuntimeError("The source system disk still exists")
        print("Source VM stopped and its writable system disk and credential store were removed.", flush=True)

        with boot_guest(work, console, "recovery", image, seed, port) as stream:
            target = receive(stream)
            if target["boot_id"] == source["boot_id"] or target["sftp_key"].split()[1] == source["sftp_key"].split()[1]:
                raise RuntimeError("Recovery VM reused source identity")
            receiver.authorize(target["sftp_key"], read_only=True)
            send(stream, {**settings, "archives": archives})
            for expected in ({"sqlite": "ok", "versions": [1, 2]}, {"rejected": "PORTABLE_DEK_REQUIRED"}):
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
    print("Fresh VM verified SQLite and DEK generations 1 and 2. OS-wrapped-only restore was rejected.", flush=True)


def main():
    os.umask(0o077)
    if sys.argv[1:] == ["--guest"]:
        guest()
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
    args = parser.parse_args()
    release = freedesktop_os_release()
    if os.geteuid() != 0 or (release["ID"], release["VERSION_ID"]) != ("ubuntu", "24.04"):
        raise SystemExit("Run as root in a disposable Ubuntu 24.04 VM.")
    with TemporaryDirectory(prefix="hostorbit-guests-", dir=args.scratch) as work, \
            TemporaryDirectory(prefix="hostorbit-console-", dir="/run") as console:
        Path(console).chmod(0o711)
        experiment(Path(work), Path(console), args.image.resolve(), args.dependencies, args.age_dir)


if __name__ == "__main__":
    main()
