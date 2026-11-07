#!/usr/bin/env python3
"""Fresh install in a disposable GitHub-hosted Ubuntu VM; never targets a user VPS."""

import argparse
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import pwd
import secrets
import select
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import time
import urllib.error
from urllib.request import Request, urlopen


REPO = Path(__file__).resolve().parents[2]
HOST_PYTHON = Path(sys.executable).resolve()
ORIGIN = "https://127.0.0.1:19449"
PORT = 18080
PASSWORD = "Fixture-Owner-password-117!"
FAKE_JOB = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"


def run(*args, check=True, input=None, timeout=60):
    result = subprocess.run([str(arg) for arg in args], input=input, capture_output=True, timeout=timeout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if check and result.returncode:
        print(result.stderr.decode(errors="replace")[-3000:], file=sys.stderr)
        raise RuntimeError(f"Fixture command failed: {Path(str(args[0])).name}")
    return result


def docker(host, *args, **kwargs):
    return run("/usr/bin/docker", "--host", host, *args, **kwargs).stdout.decode().strip()


def wait_for(check, description, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.1)
    raise RuntimeError(description)


def owner_create():
    """Exercise the actual local CLI with terminal echo disabled by getpass."""
    master, slave = pty.openpty()
    process = subprocess.Popen(["/opt/hostorbit/admin", "create-owner", "--username", "roman"],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    output, sent = b"", 0
    try:
        deadline = time.monotonic() + 20
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
            if sent == 0 and b"Owner password: " in output:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
            if sent == 1 and b"Confirm password: " in output:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
        process.wait(timeout=5)
        if process.returncode or sent != 2 or PASSWORD.encode() in output:
            raise RuntimeError("Owner terminal bootstrap failed or echoed the password")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


def migration_rehearsal(root):
    """Use only code/assets from the installed signed wheel on a legacy fixture."""
    legacy = root / "legacy"
    legacy.mkdir(mode=0o700)
    path = legacy / "controller.sqlite3"
    code = f"""import sqlite3
from contextlib import closing
from pathlib import Path
from hostorbit.auth import AuthService
from hostorbit.database import Store
from hostorbit.migrations import historical_schema
p=Path({str(path)!r})
p.touch(mode=0o600)
with closing(sqlite3.connect(p,autocommit=True)) as db:
 db.execute('PRAGMA journal_mode=WAL')
 db.executescript(historical_schema())
s=Store(p)
a=AuthService(s)
a.create_owner(a.issue_bootstrap(),'legacy-owner',{PASSWORD!r})
a.login('legacy-owner',{PASSWORD!r},ip='192.0.2.77',correlation='install-lab')
print(s.verify_audit())
"""
    before = run("/opt/hostorbit/venv/bin/python", "-c", code).stdout.decode().strip()
    output = root / "migration-review"
    response = run("/opt/hostorbit/venv/bin/hostorbit", "--database", path,
                   "migration-rehearsal", "--output", output)
    report = json.loads(response.stdout)
    if (report["status"] != "REHEARSAL_PASSED" or report["applied_to_source"] is not False
            or report["live_apply"] != "BLOCKED" or report["source_audit_head"] != before
            or report["preserved_table_rows"]["users"] != 1 or report["preserved_table_rows"]["sessions"] != 1):
        raise RuntimeError("Installed historical migration rehearsal failed")
    with sqlite3.connect(path) as source, sqlite3.connect(output / "migrated.sqlite3") as copied:
        if (source.execute("PRAGMA user_version").fetchone() != (1,)
                or copied.execute("PRAGMA user_version").fetchone() != (2,)
                or source.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone() != (before,)):
            raise RuntimeError("Rehearsal changed the source or failed to migrate its private copy")
    print("Installed wheel CLI rehearsed schema 1 to 2; Owner/session/audit survived and live schema stayed at 1.", flush=True)


def writer_barrier(host, ids):
    """The installed wheel coordinates actual container UIDs and native services."""
    code = '''import json, os, sys
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.database import DataAccess, Store
from hostorbit.errors import Denied
c=json.load(open('/etc/hostorbit/runtime.json'))
a=Admission(c['writer_directory'],timeout=0.05)
s=Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']),writers=a)
for target in ('state.json','writers.lock'):
 try: os.unlink(Path(c['writer_directory'])/target)
 except OSError: pass
 else: raise AssertionError('container replaced the root-owned latch')
expected=sys.argv[1]
assert a.state()['phase']==expected
for kind in ('business','dispatch','control'):
 try:
  with s.write(kind=kind) as db:
   assert expected=='CLOSING_ADMISSION' and kind=='control'
   Store.event(db,at=1,actor='installation-lab',kind='snapshot.checkpoint',target='controller',outcome='SUCCEEDED',correlation='writer-barrier')
 except Denied as e:
  assert e.code==('WRITER_BARRIER_TIMEOUT' if expected=='SHORT_BARRIER' else 'WRITER_ADMISSION_CLOSED')
  assert expected=='SHORT_BARRIER' or kind!='control'
print('CONTAINER_WRITERS_VERIFIED')
'''
    fixture = '''import json, subprocess, sys
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.database import DataAccess, Store
from hostorbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/hostorbit/runtime.json'))
a=Admission(c['writer_directory'])
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',a)
def check(phase):
 for identity in json.loads(sys.argv[2]):
  p=subprocess.run(['/usr/bin/docker','--host',sys.argv[1],'exec',identity,'python','-c',sys.argv[3],phase],capture_output=True,timeout=8)
  assert p.returncode==0, p.stderr.decode()[-2000:]
  assert p.stdout.strip()==b'CONTAINER_WRITERS_VERIFIED'
 return True
def capture(_):
 check('SHORT_BARRIER')
 s=Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']))
 return s.verify_audit()
_,result=co.snapshot(lambda:check('CLOSING_ADMISSION'),capture)
assert result and a.state()['phase']=='OPEN'
with co.journal.connect() as db:
 assert [r['phase'] for r in db.execute('SELECT phase FROM transitions ORDER BY seq')][-4:]==['REQUESTED','CLOSING_ADMISSION','SHORT_BARRIER','BARRIER_RELEASED']
print('INSTALLED_BARRIER_VERIFIED')
'''
    result = run("/opt/hostorbit/venv/bin/python", "-c", fixture, host, json.dumps(list(ids.values())), code, timeout=45)
    if result.stdout.strip() != b"INSTALLED_BARRIER_VERIFIED":
        raise RuntimeError("Installed writer barrier did not verify")
    recovery = '''import json, os, select, signal, subprocess, sys
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.runtime.ipc import Client
from hostorbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/hostorbit/runtime.json'))
child=''' + '"""' + '''import json, time
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/hostorbit/runtime.json'))
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
def capture(_):
 print('SHORT_BARRIER',flush=True)
 time.sleep(120)
co.snapshot(lambda:True,capture)
''' + '"""' + '''
p=subprocess.Popen([sys.executable,'-c',child],stdout=subprocess.PIPE,start_new_session=True)
try:
 assert select.select([p.stdout],[],[],10)[0]
 assert p.stdout.readline().strip()==b'SHORT_BARRIER'
 os.killpg(p.pid,signal.SIGKILL)
 p.wait(timeout=5)
 # Authenticated root IPC triggers the independent supervisor watchdog, not
 # a test-side recover() call or a restart of the controller installation.
 Client(c['gate_socket'],server_uids={0}).call('time.health',{})
 assert Admission(c['writer_directory']).state()['phase']=='OPEN'
 co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
 with co.journal.connect() as db:
  assert db.execute('SELECT phase FROM transitions ORDER BY seq DESC LIMIT 1').fetchone()['phase']=='ABORTED'
finally:
 if p.poll() is None:
  os.killpg(p.pid,signal.SIGKILL)
  p.wait(timeout=5)
print('WATCHDOG_RECOVERY_VERIFIED')
'''
    if run("/opt/hostorbit/venv/bin/python", "-c", recovery, timeout=20).stdout.strip() != b"WATCHDOG_RECOVERY_VERIFIED":
        raise RuntimeError("Installed supervisor did not recover the killed snapshot coordinator")
    for service in ("hostorbit-broker.service", "hostorbit-supervisor.service"):
        if run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active":
            raise RuntimeError("Barrier interrupted a host service")
    if json.loads(docker(host, "inspect", ids["worker"]))[0]["RestartCount"] != 0:
        raise RuntimeError("Closing admission crashed the idle Worker")
    print("Installed root latch stayed read-only in both containers; checkpoints drained, all critical writers paused, and supervisor recovered a SIGKILL without restart.", flush=True)


def vault_pin():
    """Fixture SSH keys only; no Owner age identity or user server is involved."""
    cfg = json.loads(Path("/etc/hostorbit/runtime.json").read_bytes())
    folder = Path("/run/hostorbit/pin-fixture")
    folder.mkdir(mode=0o700)
    run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", folder / "ssh-key")
    os.chown(folder / "ssh-key", cfg["broker_uid"], cfg["broker_gid"])
    os.chown(folder, cfg["broker_uid"], cfg["broker_gid"])
    with sqlite3.connect(cfg["database"]) as db:
        owner, = db.execute("SELECT id FROM users WHERE role='Owner'").fetchone()
    provision = '''import json, os, sys
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.runtime.storage import protected_bytes
from hostorbit.runtime.vault import Vault
c=json.load(open('/etc/hostorbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',systemd_credential=True,writers=Admission(c['writer_directory']))
key=protected_bytes(sys.argv[1],owner=os.geteuid(),maximum=8192,private=True)
for version in (1,2):
 ref=v.import_ssh('01JCYQZ4T9V8MNVYEH3D2M7Q1C',version,key,owner_id=sys.argv[2],worker_uid=c['worker_uid'],target='01JCYQZ4T9V8MNVYEH3D2M7Q1A')
 if version==1: v.revoke(ref)
print('FIXTURE_VERSIONS_IMPORTED')
'''
    imported = run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=hostorbit-pin-fixture",
                   "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
                   "--property=UMask=0077", "--property=LimitCORE=0",
                   "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
                   "/opt/hostorbit/venv/bin/python", "-c", provision, folder / "ssh-key", owner)
    if imported.stdout.strip() != b"FIXTURE_VERSIONS_IMPORTED":
        raise RuntimeError("Broker fixture provisioning failed")
    capture = '''import hashlib, json
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.pins import capture_with_systemd
c=json.load(open('/etc/hostorbit/runtime.json'))
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
snapshot_id,result=co.snapshot(lambda:True,capture_with_systemd)
assert result['secrets']==2 and result['objects']==2 and result['portable_keys_exported'] is False and result['backup_gate']=='DENIED'
root=Path(c['broker_directory'])/'snapshot-pins'/snapshot_id
raw=(root/'pin.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()==result['manifest_sha256']
manifest=json.loads(raw)
assert manifest['key_generations']==[1] and {r['state'] for r in manifest['references']}=={'ACTIVE','REVOKED'}
for f in manifest['files']:
 data=(root/f['path']).read_bytes()
 assert len(data)==f['size'] and hashlib.sha256(data).hexdigest()==f['sha256']
 assert b'-----BEGIN OPENSSH PRIVATE KEY-----' not in data
print('INSTALLED_VAULT_PIN_VERIFIED')
'''
    result = run("/opt/hostorbit/venv/bin/python", "-c", capture, timeout=35)
    if result.stdout.strip() != b"INSTALLED_VAULT_PIN_VERIFIED":
        raise RuntimeError("Installed Vault pin helper failed")
    print("Sandboxed Broker-UID helper pinned active/revoked ciphertext and both SQLite journals under the Root barrier; portable DEK export and Backup Gate remained disabled.", flush=True)


def controller_archive(root, bundle):
    """One-VM crypto fixture, not an independent workstation/DR attestation."""
    # This binary stays in CI's fixture area, outside the Controller installation.
    keygen = bundle.parent / "hostorbit-install-age/age/age-keygen"
    identity = run(keygen).stdout
    recipient = run(keygen, "-y", input=identity).stdout.decode().strip()
    anchor = root / "independent-controller.pub"
    anchor.write_bytes(Path("/etc/hostorbit/gate.pub").read_bytes())
    anchor.chmod(0o600)
    result = json.loads(run("/opt/hostorbit/venv/bin/hostorbit-backup", "create", "--recipient", recipient, timeout=210).stdout)
    if (result["status"] != "LOCAL_SIGNED_ONLY" or result["portable_keys_exported"] is not True
            or result["off_host"] is not False or result["restore_verified"] is not False or result["backup_gate"] != "DENIED"):
        raise RuntimeError("Local archive falsely reported completed recovery/Backup Gate")
    verified = json.loads(run("/opt/hostorbit/venv/bin/hostorbit-backup", "verify", "--ciphertext", result["ciphertext"],
                              "--provenance", result["provenance"], "--trusted-key", anchor).stdout)
    if verified["status"] != "PROVENANCE_VERIFIED" or verified["payload_integrity"] != "NOT_DECRYPTED":
        raise RuntimeError("Installed provenance verifier reported false payload verification")
    read, write = os.pipe()
    try:
        os.write(write, identity)
        os.close(write)
        write = None
        decrypted = subprocess.run(["/opt/hostorbit/tools/age", "--decrypt", "--identity", f"/dev/fd/{read}", result["ciphertext"]],
                                   pass_fds=(read,), capture_output=True, timeout=20)
        if decrypted.returncode:
            raise RuntimeError("Fixture Owner could not decrypt the installed native stream")
    finally:
        os.close(read)
        if write is not None:
            os.close(write)
    # Validate only in-memory members. No extractall or plaintext DEK/identity
    # file is created by this fixture or by the Controller.
    import io
    import tarfile
    import base64
    from nacl.secret import Aead
    with tarfile.open(fileobj=io.BytesIO(decrypted.stdout)) as tar:
        names = tar.getnames()
        if "vault/portable-keys.json" not in names or any("signing.key" in n or "broker-dek" in n for n in names):
            raise RuntimeError("Portable archive omitted keys or included a host-bound/private authority key")
        keyset = json.load(tar.extractfile("vault/portable-keys.json"))
        if len(keyset["generations"]) != 1 or keyset["generations"][0]["version"] != 1:
            raise RuntimeError("Portable archive omitted its supported working key generation")
        pin = json.load(tar.extractfile("vault/pin.json"))
        if {ref["state"] for ref in pin["references"]} != {"ACTIVE", "REVOKED"}:
            raise RuntimeError("Archive lost the revoked version")
        for record in pin["files"]:
            data = tar.extractfile("vault/" + record["path"]).read()
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise RuntimeError("Decrypted pinned object differs from its manifest")
        # Recover the working key solely from the encrypted portable member;
        # neither source OS wrapping key nor source runtime credential is read.
        aead = Aead(base64.b64decode(keyset["generations"][0]["key"], validate=True))
        with sqlite3.connect(":memory:") as db:
            db.deserialize(tar.extractfile("vault/vault.sqlite3").read())
            for ref in pin["references"]:
                metadata, state = db.execute("SELECT metadata,state FROM secrets WHERE ref=?", (ref["ref"],)).fetchone()
                raw = tar.extractfile("vault/objects/" + ref["object_digest"]).read()
                plaintext = aead.decrypt(raw, metadata.encode())
                if state != ref["state"] or not plaintext.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
                    raise RuntimeError("Portable working DEK did not recover the pinned SSH fixture version")
                del plaintext
        source = json.load(tar.extractfile("controller/manifest.json"))
        for record in source["files"]:
            data = tar.extractfile("controller/" + record["path"]).read()
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise RuntimeError("Decrypted Controller member differs from its pinned source")
    print("Installed Broker streamed portable DEK into age without a plaintext key file; saved public anchor verified ciphertext/provenance and fixture Owner decrypted the full Controller/Vault archive.", flush=True)
    return result, identity


def sftp_publication(root, local_archive, identity):
    """Real SSH/SFTP; same hosted VM with a separate network/storage namespace."""
    from sftp_receiver import receiver
    cfg = json.loads(Path("/etc/hostorbit/runtime.json").read_bytes())
    target_id, secret_id = "01JCYQZ4T9V8MNVYEH3D2M7Q1F", "01JCYQZ4T9V8MNVYEH3D2M7Q1E"
    folder = Path("/run/hostorbit/sftp-client")
    folder.mkdir(mode=0o700)
    run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", folder / "client")
    public = (folder / "client.pub").read_text()
    os.chown(folder / "client", cfg["broker_uid"], cfg["broker_gid"])
    os.chown(folder, cfg["broker_uid"], cfg["broker_gid"])
    with sqlite3.connect(cfg["database"]) as db:
        owner = db.execute("SELECT id FROM users WHERE role='Owner'").fetchone()[0]
    run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=hostorbit-sftp-import-fixture",
        "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
        "--property=UMask=0077", "--property=LimitCORE=0",
        "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
        "/opt/hostorbit/venv/bin/hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json", "import-backup-key",
        "--key-file", folder / "client", "--secret-id", secret_id, "--owner-id", owner, "--target", target_id)
    (folder / "client").unlink()
    provenance = json.loads(Path(local_archive["provenance"]).read_bytes())
    recipient = provenance["claims"]["recipient"]
    target_file = Path("/etc/hostorbit/backup-target.json")

    def create():
        return json.loads(run("/opt/hostorbit/venv/bin/hostorbit-backup", "create", "--recipient", recipient, timeout=210).stdout)

    def phase(snapshot_id):
        with sqlite3.connect(Path(cfg["supervisor_directory"]) / "snapshots/snapshots.sqlite3") as db:
            return db.execute("SELECT phase FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()[0]

    def publish(archive, expected=None):
        response = run("/opt/hostorbit/venv/bin/hostorbit-backup", "publish", "--snapshot-id", archive["snapshot_id"], check=False, timeout=180)
        if expected is not None:
            if response.returncode == 0 or expected.encode() not in response.stderr or phase(archive["snapshot_id"]) != "FAILED":
                raise RuntimeError("SFTP negative path failed: " + response.stderr.decode(errors="replace")[-300:])
            return
        if response.returncode:
            raise RuntimeError("SFTP publication failed: " + response.stderr.decode(errors="replace")[-300:])
        result = json.loads(response.stdout)
        if result["status"] != "PUBLISHED" or result["backup_gate"] != "DENIED" or result["restore_verified"] is not False or phase(archive["snapshot_id"]) != "PUBLISHED":
            raise RuntimeError("SFTP publisher falsely reported completion or restore readiness")

    with receiver(root, public) as remote:
        target = {"v": 1, "enabled": True, "id": target_id, "ip": "10.241.0.2", "port": 2223,
                  "allowed_cidrs": ["10.241.0.0/30"], "host_key": remote.host_key, "username": remote.account,
                  "directory": "/store", "secret_ref": secret_id + ":v1", "policy_revision": 1}
        def configure(value):
            target_file.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            target_file.chmod(0o644)
        configure(target)
        first = create()
        publish(first)
        final = remote.store / first["snapshot_id"]
        expected_cipher = Path(first["ciphertext"]).read_bytes()
        if (final / "controller.age").read_bytes() != expected_cipher or not (final / "COMPLETE").is_file():
            raise RuntimeError("SFTP final bytes/marker differ from the signed source")
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in final.iterdir()}
        publish(first)
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in final.iterdir()}
        if before != after:
            raise RuntimeError("Idempotent publication overwrote final data")
        # Ciphertext survived independently of the local publisher's staging;
        # verify its signed origin with the separately saved public anchor.
        run("/opt/hostorbit/venv/bin/hostorbit-backup", "verify", "--ciphertext", final / "controller.age",
            "--provenance", final / "provenance.json", "--trusted-key", root / "independent-controller.pub")
        read, write = os.pipe()
        try:
            os.write(write, identity)
            os.close(write)
            write = None
            recovered = subprocess.run(["/opt/hostorbit/tools/age", "--decrypt", "--identity", f"/dev/fd/{read}", str(final / "controller.age")],
                                       pass_fds=(read,), capture_output=True, timeout=20)
            if recovered.returncode:
                raise RuntimeError("Published SFTP archive did not decrypt with the fixture Owner identity")
        finally:
            os.close(read)
            if write is not None:
                os.close(write)
        import io, tarfile, base64
        from nacl.secret import Aead
        with tarfile.open(fileobj=io.BytesIO(recovered.stdout)) as tar:
            keys = json.load(tar.extractfile("vault/portable-keys.json"))
            aead = Aead(base64.b64decode(keys["generations"][0]["key"], validate=True))
            with sqlite3.connect(":memory:") as db:
                db.deserialize(tar.extractfile("vault/vault.sqlite3").read())
                metadata, digest = db.execute("SELECT metadata,object_digest FROM secrets WHERE ref=?", (secret_id + ":v1",)).fetchone()
                raw = tar.extractfile("vault/objects/" + digest).read()
                if json.loads(metadata)["purpose"] != "backup.sftp" or not aead.decrypt(raw, metadata.encode()).startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
                    raise RuntimeError("Published archive lost its purpose-bound SFTP credential")
        run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", remote.root / "wrong-host")
        wrong = {**target, "host_key": " ".join((remote.root / "wrong-host.pub").read_text().split()[:2])}
        configure(wrong)
        bad_host = create()
        publish(bad_host, "SFTP_HOST_KEY_MISMATCH")
        configure(target)
        outage = create()
        remote.stop()
        publish(outage, "SFTP_NETWORK_OR_STORAGE_UNAVAILABLE")
        if json.load(urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=5))["status"] != "alive":
            raise RuntimeError("SFTP outage interrupted the Controller API")
        remote.start()
        publish(outage)
        full = create()
        filler = remote.store / "filler"
        try:
            with filler.open("wb") as stream:
                while True:
                    stream.write(b"x" * 65536)
        except OSError as error:
            import errno
            if error.errno != errno.ENOSPC:
                raise
        publish(full, "SFTP_REMOTE_FAILED")
        if (remote.store / full["snapshot_id"]).exists():
            raise RuntimeError("ENOSPC exposed an eligible final archive")
        filler.unlink()
        publish(full)
        # A corrupted existing final archive is detected and not repaired by
        # overwriting the old recovery point.
        damaged = final / "controller.age"
        damaged.write_bytes(b"corrupted fixture archive")
        publish(first, "SFTP_READBACK_MISMATCH")
        if damaged.read_bytes() != b"corrupted fixture archive":
            raise RuntimeError("Publisher overwrote corrupted existing backup")
        revoked = create()
        revoke = '''import json,os
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.runtime.vault import Vault
c=json.load(open('/etc/hostorbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',systemd_credential=True,writers=Admission(c['writer_directory']))
v.revoke('01JCYQZ4T9V8MNVYEH3D2M7Q1E:v1')
'''
        run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=hostorbit-sftp-revoke-fixture",
            "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
            "--property=UMask=0077", "--property=LimitCORE=0", "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
            "/opt/hostorbit/venv/bin/python", "-c", revoke)
        publish(revoked, "SECRET_NOT_ACTIVE")
        if (remote.store / revoked["snapshot_id"]).exists():
            raise RuntimeError("Revoked SFTP identity published a new archive")
    print("Real pinned OpenSSH SFTP publication passed fsync/readback/final marker, no-overwrite replay, wrong-host refusal, outage/ENOSPC recovery, corruption and revoked-key rejection; API stayed available.", flush=True)


def credential_binding(root, source):
    """A second host-key domain in a private mount namespace, not a real VPS."""
    other = root / "other-host"
    other.mkdir(mode=0o700)
    code = """import os, pathlib, subprocess, sys
other, source = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def run(*args, data=None):
 return subprocess.run(args,input=data,capture_output=True,timeout=15)
assert run('/usr/bin/mount','--make-rprivate','/').returncode==0
assert run('/usr/bin/mount','--bind',str(other),'/var/lib/systemd').returncode==0
assert run('/usr/bin/systemd-creds','setup').returncode==0
wrong=run('/usr/bin/systemd-creds','decrypt','--name=broker-dek',str(source),'-')
assert wrong.returncode!=0 and not wrong.stdout
key=os.urandom(32)
wrapped=run('/usr/bin/systemd-creds','encrypt','--with-key=host','--name=broker-dek','-','-',data=key)
assert wrapped.returncode==0 and len(wrapped.stdout)>32
target=other/'target.cred'
target.write_bytes(wrapped.stdout)
target.chmod(0o600)
opened=run('/usr/bin/systemd-creds','decrypt','--name=broker-dek',str(target),'-')
assert opened.returncode==0 and opened.stdout==key
print('HOST_BINDING_VERIFIED')
"""
    response = run("/usr/bin/unshare", "--mount", "--fork", "/usr/bin/python3", "-I", "-c", code, other, source)
    if response.stdout.strip() != b"HOST_BINDING_VERIFIED":
        raise RuntimeError("Host-bound credential verification failed")
    # Target-encrypted ciphertext is not valid under the original host's key.
    denied = run("/usr/bin/systemd-creds", "decrypt", "--name=broker-dek", other / "target.cred", "-", check=False)
    if denied.returncode == 0 or denied.stdout:
        raise RuntimeError("Another host's sealed credential was accepted")
    wrong_name = run("/usr/bin/systemd-creds", "decrypt", "--name=another-credential", source, "-", check=False)
    if wrong_name.returncode == 0 or wrong_name.stdout:
        raise RuntimeError("Credential name binding was not enforced")
    print("Encrypted OS credential rejected another host key and another name; target resealing verified without a plaintext file.", flush=True)


@contextmanager
def tls_proxy(root):
    run("/usr/bin/openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", root / "tls.key",
        "-out", root / "tls.crt", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in ("host", "content-length", "connection", "x-forwarded-for", "x-forwarded-proto")}
            headers.update({"Host": "127.0.0.1:19449", "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})
            request = Request(f"http://127.0.0.1:{PORT}" + self.path, data=body if self.command == "POST" else None,
                              headers=headers, method=self.command)
            try:
                response = urlopen(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() not in ("connection", "transfer-encoding", "content-length", "server", "date"):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        do_GET = forward
        do_POST = forward

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "tls.crt", root / "tls.key")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19449), Proxy)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ssl.create_default_context(cafile=str(root / "tls.crt"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def recovery_installation(args, base, foreign):
    """Source removal and fresh recovered services on this one disposable VM.

    This is service integration, not physical host independence or a manual
    fencing/restore attestation. Never expose this cleanup as a product command.
    """
    global PORT
    units = ("hostorbit-compose.service", "hostorbit-broker.socket", "hostorbit-supervisor.socket",
             "hostorbit-broker.service", "hostorbit-supervisor.service")
    run("/usr/bin/systemctl", "stop", *units, timeout=80)
    docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file", "/etc/hostorbit/compose.json", "down", timeout=60)
    run("/usr/bin/systemctl", "disable", *units, check=False)
    for unit in units:
        (Path("/etc/systemd/system") / unit).unlink()
    for path in ("/opt/hostorbit", "/etc/hostorbit", "/var/lib/hostorbit", "/run/hostorbit"):
        shutil.rmtree(path)
    for path in ("/etc/tmpfiles.d/hostorbit.conf", "/etc/sysusers.d/hostorbit.conf"):
        Path(path).unlink()
    run("/usr/bin/systemctl", "daemon-reload")
    run("/usr/bin/systemctl", "reset-failed", *units, check=False)
    for name in ("ho-api", "ho-worker", "ho-broker"):
        run("/usr/sbin/userdel", name)
    for name in ("ho-api", "ho-worker", "ho-broker", "ho-app-db", "ho-broker-rpc", "ho-gate-rpc"):
        run("/usr/sbin/groupdel", name, check=False)
    print("Disposable fixture removed its source installation; only the separately imported private recovery layout remains.", flush=True)
    isolated_at = int(time.time())
    # Use a fresh high port on this same VM rather than depending on the old
    # source listener's TCP TIME_WAIT lifetime. Production port checks stay strict.
    PORT = 18081
    base = list(base)
    base[base.index("--port") + 1] = str(PORT)
    state = "/var/lib/hostorbit-rescue-lab/target-state"
    restore = [*base, "--recovery-state", state]
    checked = json.loads(run(*restore, "--check", timeout=180).stdout)
    if checked["recovery"] != "READ_ONLY_RECOVERY" or Path("/opt/hostorbit").exists() or Path(state, "installation.claim.json").exists():
        raise RuntimeError("Recovery preflight created an installation or consumed the import")
    result = json.loads(run(*restore, timeout=420).stdout)
    if result["recovery"] != "READ_ONLY_RECOVERY" or result["owner_setup"] != "RESTORED_OWNER":
        raise RuntimeError("Recovery install lost its mode or recreated Owner bootstrap")
    cfg = json.loads(Path("/etc/hostorbit/runtime.json").read_bytes())
    worker = docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file", "/etc/hostorbit/compose.json", "ps", "--quiet", "worker")
    # The original container owns its lifetime lock, so use its normal process
    # health and a separate no-claim assertion against the installed journals.
    status = json.loads(docker(args.docker_host, "inspect", worker))[0]
    if not status["State"]["Running"] or status["RestartCount"]:
        raise RuntimeError("Recovered Worker was not stably idle")
    verify = """import json
from pathlib import Path
from hostorbit.admission import Admission
from hostorbit.database import DataAccess,Store
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.coordinator import Coordinator
from hostorbit.runtime.policy import Policy
from nacl.secret import Aead
import subprocess,sqlite3,hashlib,stat
c=json.load(open('/etc/hostorbit/runtime.json'))
w=Admission(c['writer_directory'])
assert w.state()['phase']=='READ_ONLY_RECOVERY'
Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']),writers=w).verify_audit()
a=Authority(c['supervisor_directory'],Policy.load(c['targets']))
with a.journal.connect() as db:
 r=db.execute('SELECT * FROM gate').fetchone()
 assert r['activated']==0 and r['state']=='RECOVERY_HOLD'
 assert db.execute('SELECT count(*) FROM attempts').fetchone()[0]==0
a.close()
key=subprocess.run(['/usr/bin/systemd-creds','decrypt','--name=broker-dek',c['vault_credential'],'-'],capture_output=True,check=True).stdout
pin=json.load(open('/var/lib/hostorbit-rescue-lab/target-data/source/pin.json'))
assert len(key)==32 and hashlib.sha256(key).hexdigest()==pin['key_fingerprints']['1']
objects=Path(c['vault_directory'])/'objects'
with sqlite3.connect(Path(c['vault_directory'])/'vault.sqlite3') as db:
 rows=db.execute('SELECT ref,metadata,object_digest,state FROM secrets ORDER BY ref').fetchall()
 assert [(r[0],r[2],r[3]) for r in rows]==[(r['ref'],r['object_digest'],r['state']) for r in pin['references']]
 for ref,metadata,digest,state in rows:
  p=objects/digest
  assert p.stat().st_uid==c['broker_uid'] and stat.S_IMODE(p.stat().st_mode)==0o600
  raw=p.read_bytes()
  assert hashlib.sha256(raw).hexdigest()==digest
  secret=Aead(key).decrypt(raw,metadata.encode())
  assert secret.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----')
  del secret
del key
Path(c['writer_directory'],'state.json').unlink()
Coordinator(Path(c['supervisor_directory'])/'snapshots',w).recover_if_idle()
assert w.state()['phase']=='READ_ONLY_RECOVERY'
print('RECOVERY_JOURNALS_VERIFIED')
"""
    if run("/opt/hostorbit/venv/bin/python", "-c", verify).stdout.strip() != b"RECOVERY_JOURNALS_VERIFIED":
        raise RuntimeError("Recovered installed journals failed verification")
    for service in ("hostorbit-broker.service", "hostorbit-supervisor.service"):
        if (run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active"
                or run("/usr/bin/systemctl", "show", "--property=NRestarts", "--value", service).stdout.strip() != b"0"):
            raise RuntimeError("Recovered native service failed startup or restarted")
    # Actual HTTPS requests into the installed API, with auth-control writes
    # allowed and business/dispatch mutations rejected by the protected profile.
    with tls_proxy(Path(state).parent) as context:
        def request(path, body=None, headers=None):
            req = Request(ORIGIN + path, data=None if body is None else json.dumps(body).encode(),
                          headers={"Origin": ORIGIN, "Content-Type": "application/json", **(headers or {})})
            try:
                return urlopen(req, context=context, timeout=10)
            except urllib.error.HTTPError as error:
                return error
        login = request("/api/v1/auth/login", {"username": "roman", "password": PASSWORD})
        if login.status != 200:
            raise RuntimeError("Restored Owner could not log in through installed HTTPS API")
        cookie = login.headers["Set-Cookie"].split(";", 1)[0]
        body = json.load(login)
        headers = {"Cookie": cookie, "X-CSRF-Token": body["csrf_token"]}
        audit = request("/api/v1/audit", headers=headers)
        if audit.status != 200:
            raise RuntimeError("Restored Owner could not read Audit")
        audit.close()
        changed = request("/api/v1/users", {"username": "blocked", "password": PASSWORD, "role": "Auditor"}, headers)
        if changed.status != 503 or json.load(changed)["code"] != "WRITER_ADMISSION_CLOSED":
            raise RuntimeError("Recovered API admitted a business write")
        job = request(f"/api/v1/resources/{FAKE_JOB}/observations", {}, {**headers, "Idempotency-Key": "recovery-blocked-request"})
        if job.status != 503 or json.load(job)["code"] != "WRITER_ADMISSION_CLOSED":
            raise RuntimeError("Recovered API admitted a new job")
    run("/usr/bin/systemctl", "restart", "hostorbit-compose.service", timeout=180)
    if json.load(urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=10))["status"] != "alive":
        raise RuntimeError("Recovered Compose did not restart")
    if foreign.getsockname() != ("127.0.0.1", 443):
        raise RuntimeError("Recovery changed a foreign listener")
    again = run(*restore, check=False, timeout=30)
    if again.returncode == 0:
        raise RuntimeError("Repeated recovery overwrote its installation")
    print("Signed recovery installation passed restored HTTPS Owner/Audit, stable idle Worker, fresh inactive Gate/Broker, persistent read-only after latch loss/restart, and blocked business/jobs/reinstall; physical DR remains unattested.", flush=True)
    activation_fixture(state, isolated_at)


def activation_terminal(arguments, answers=()):
    master, slave = pty.openpty()
    process = subprocess.Popen(["/opt/hostorbit/venv/bin/hostorbit-activate", *arguments], stdin=slave, stdout=slave,
                               stderr=slave, start_new_session=True)
    os.close(slave)
    output, sent = bytearray(), 0
    try:
        deadline = time.monotonic() + 240
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    break
            if sent < len(answers) and answers[sent][0] in output:
                os.write(master, (answers[sent][1] + "\n").encode())
                sent += 1
        process.wait(timeout=5)
        while select.select([master], [], [], 0)[0]:
            try:
                output.extend(os.read(master, 4096))
            except OSError:
                break
        if process.returncode or sent != len(answers) or PASSWORD.encode() in output:
            # Do not print captured terminal content containing authentication.
            raise RuntimeError("Installed activation console failed or echoed its password")
        return next(json.loads(line) for line in bytes(output).splitlines() if line.startswith(b"{") and line.endswith(b"}"))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


def activation_fixture(state, isolated_at):
    """Simulated local operator on the disposable VM, no independent DR claim."""
    source = Path(state).parent / "target-data"
    receipt = json.loads((source / "recovery.json").read_bytes())
    if (source / "source/gate.pub").read_bytes() == Path("/etc/hostorbit/gate.pub").read_bytes():
        raise RuntimeError("Recovered instance reused the removed source identity")
    old_host = run("/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256").stdout.decode().split()[1]
    while int(time.time()) - isolated_at < 10:
        time.sleep(0.2)
    report = {"v": 1, "type": "hostorbit.manual-isolation", "source_instance": receipt["source_instance"],
        "target_instance": receipt["target_id"], "source_backup_hash": receipt["source_backup_hash"], "dependencies_reviewed": True,
        "isolation": {"method": "verified_local_stop", "console": "CI/root-console/source-installation-removal",
            "operator": "CI-simulated-Owner-not-human-attestation", "old_host_key": old_host,
            "worker_stopped": True, "scheduler_stopped": True, "autostart_blocked": True,
            "old_permissions_revoked": True, "dangerous_operations_stopped": True,
            "observations": [{"source": "CI/source-units-and-keys-removed", "at_utc": isolated_at, "isolated": True},
                {"source": "CI/independent-instance-key-comparison", "at_utc": int(time.time()), "isolated": True}]}, "targets": {}}
    path = Path(state).parent / "manual-isolation.json"
    path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
    path.chmod(0o600)
    base = ["--state", state, "--old-host-key", old_host]
    review = activation_terminal([*base, "prepare", "--report", str(path), "--policy", "/etc/hostorbit/targets.json"])
    result = activation_terminal([*base, "activate", "--plan-id", review["plan_id"]],
        [(b"Exact confirmation SHA-256", review["confirmation_sha256"]), (b"Owner username:", "roman"), (b"Owner password:", PASSWORD)])
    if result["status"] != "ACTIVE" or result["allowed_targets"] or result["restore_verified"]:
        raise RuntimeError("Fixture activation broadened its empty inventory or claimed DR attestation")
    for unit in ("hostorbit-compose.service", "hostorbit-supervisor.service", "hostorbit-broker.service"):
        run("/usr/bin/systemctl", "is-active", unit)
    run("/usr/bin/systemctl", "restart", "hostorbit-supervisor.service", timeout=30)
    verify = """import json
from hostorbit.admission import Admission
from hostorbit.database import DataAccess,Store
from hostorbit.runtime.authority import Authority
from hostorbit.runtime.policy import Policy
c=json.load(open('/etc/hostorbit/runtime.json'))
w=Admission(c['writer_directory'])
assert w.state()['phase']=='OPEN'
a=Authority(c['supervisor_directory'],Policy.load(c['targets']),writers=w)
with a.journal.connect() as db:
 r=a._gate(db)
 assert r['activated']==1 and r['state']=='NORMAL'
assert a.recovery_authorization['allowed_targets']==[]
a.close()
s=Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']),writers=w)
s.verify_audit()
with s.write() as db:
 s.event(db,at=1,actor='fixture',kind='fixture.after_activation',target='controller',outcome='SUCCEEDED',correlation='native-activation')
print('ACTIVATION_RECORD_VERIFIED')
"""
    if run("/opt/hostorbit/venv/bin/python", "-c", verify).stdout.strip() != b"ACTIVATION_RECORD_VERIFIED":
        raise RuntimeError("Signed activation record did not survive supervisor restart")
    print("Installed local Owner activation console passed separate digest/password, durable signed empty-inventory authorization, business admission and supervisor restart; manual isolation was simulated and VPS rotation/physical DR are not attested by this fixture.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--docker-host", required=True)
    args = parser.parse_args()
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted Ubuntu VM")
    # Refuse to clean up anything unless all installation namespaces are absent.
    for path in ("/opt/hostorbit", "/etc/hostorbit", "/var/lib/hostorbit", "/run/hostorbit",
                 "/etc/tmpfiles.d/hostorbit.conf", "/etc/sysusers.d/hostorbit.conf"):
        if Path(path).exists():
            raise SystemExit("Fixture installation namespace already exists")
    base = [str(HOST_PYTHON), str(REPO / "deploy/installer.py"), "install", "--bundle", str(args.bundle),
            "--trust-key", str(args.trust_key), "--development", "--origin", ORIGIN,
            "--port", str(PORT), "--docker-host", args.docker_host]
    with tempfile.TemporaryDirectory(prefix="hostorbit-install-lab-", dir="/run") as temp:
        root = Path(temp)
        # setup-docker-action puts its daemon below runner's private home. The
        # capability-free root Compose unit must not gain DAC override merely
        # to traverse that test-only directory. Bind the same socket into this
        # root-owned lab directory, like /run/docker.sock on a normal host.
        daemon_socket = root / "docker.sock"
        daemon_socket.touch(mode=0o600)
        run("/usr/bin/mount", "--bind", args.docker_host.removeprefix("unix://"), daemon_socket)
        args.docker_host = "unix://" + str(daemon_socket)
        base[base.index("--docker-host") + 1] = args.docker_host
        # Independent trust root, not a public key automatically accepted from the bundle.
        trusted = root / "trusted.pub"
        trusted.write_bytes(args.trust_key.read_bytes())
        trusted.chmod(0o600)
        base[base.index("--trust-key") + 1] = str(trusted)
        foreign = socket.socket()
        foreign.bind(("127.0.0.1", 443))
        foreign.listen()
        foreign_identity = foreign.fileno()
        installed = False
        opt_mode = Path("/opt").stat().st_mode & 0o7777
        try:
            # Hosted runners intentionally expose /opt as 0777. A real native
            # Controller must not trust a replaceable installation parent.
            # Modify it only in this explicitly disposable VM and restore it.
            Path("/opt").chmod(0o777)
            unsafe = run(*base, "--check", check=False, timeout=30)
            if unsafe.returncode == 0 or b"INSTALLATION_PARENT_UNTRUSTED" not in unsafe.stderr:
                raise RuntimeError("Installer trusted a world-writable permanent parent")
            Path("/opt").chmod(0o755)
            print("Unsafe installation parent refused before changes; disposable fixture now uses root-owned 0755 parents.", flush=True)
            # Complete cryptographic preflight must not create an installation.
            run(*base, "--check", timeout=90)
            if Path("/opt/hostorbit").exists():
                raise RuntimeError("Preflight created persistent installation state")
            print("Signed bundle preflight passed without creating application state.", flush=True)
            response = run(*base, timeout=420)
            result = json.loads(response.stdout)
            if result.get("recovery") != "NOT_READY" or result.get("installed") is not True:
                raise RuntimeError("Installation reported false readiness")
            installed = True
            metadata = json.loads(Path("/opt/hostorbit/installation.json").read_bytes())
            cfg = json.loads(Path("/etc/hostorbit/runtime.json").read_bytes())
            age_tool = Path("/opt/hostorbit/tools/age")
            if (age_tool.stat().st_uid != 0 or age_tool.stat().st_mode & 0o777 != 0o755
                    or hashlib.sha256(age_tool.read_bytes()).hexdigest() != "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c"
                    or run(age_tool, "--version").stdout.strip() != b"v1.3.2"):
                raise RuntimeError("Installed age binary did not match the signed pinned release")
            print("Signed bundle installed the pinned age v1.3.2 executable as a root-owned host tool.", flush=True)
            ids = {name: docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file",
                               "/etc/hostorbit/compose.json", "ps", "--quiet", name) for name in ("api", "worker")}
            entries = {name: json.loads(docker(args.docker_host, "inspect", identity))[0] for name, identity in ids.items()}
            if entries["api"]["Image"] != metadata["image_id"] or entries["worker"]["Image"] != metadata["image_id"]:
                raise RuntimeError("Unverified image executed")
            if entries["worker"]["HostConfig"]["NetworkMode"] != "none" or not entries["api"]["HostConfig"]["ReadonlyRootfs"]:
                raise RuntimeError("Installed namespace isolation differs from the contract")
            published = entries["api"]["NetworkSettings"]["Ports"]["8000/tcp"]
            if published != [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}]:
                raise RuntimeError("API was not published exclusively on loopback")
            if foreign.fileno() != foreign_identity or foreign.getsockname() != ("127.0.0.1", 443):
                raise RuntimeError("Foreign listener changed")
            for service in ("hostorbit-broker.service", "hostorbit-supervisor.service", "hostorbit-compose.service"):
                if run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active":
                    raise RuntimeError("Installed systemd service is inactive")
            print("Real systemd Broker/supervisor and isolated API/Worker containers started; foreign port 443 stayed untouched.", flush=True)
            code = """import json
from hostorbit.runtime.ipc import Client
from hostorbit.errors import Denied
c=json.load(open('/etc/hostorbit/runtime.json'))
out={}
for name,operation in [('gate_socket','attempt.status'),('broker_socket','receipt.get')]:
 try: Client(c[name],server_uids={0,c['broker_uid']}).call(operation,{'job_id':'01JCYQZ4T9V8MNVYEH3D2M7Q1A'})
 except Denied as e: out[name]=e.code
print(json.dumps(out))
"""
            reached = json.loads(docker(args.docker_host, "exec", ids["worker"], "python", "-c", code))
            if reached != {"gate_socket": "ATTEMPT_NOT_FOUND", "broker_socket": "RECEIPT_NOT_TERMINAL"}:
                raise RuntimeError("Worker did not authenticate with its actual container peer credentials")
            denied = json.loads(docker(args.docker_host, "exec", ids["api"], "python", "-c", code))
            if denied != {"gate_socket": "RPC_UNAVAILABLE", "broker_socket": "RPC_UNAVAILABLE"}:
                raise RuntimeError("Backend reached a host privilege socket")
            key_path = Path("/etc/hostorbit/credentials/broker-dek.cred")
            if key_path.stat().st_mode & 0o777 != 0o600 or key_path.stat().st_uid != 0 or key_path.stat().st_size <= 32:
                raise RuntimeError("Runtime credential source is not root-private")
            if Path("/etc/hostorbit/credentials/broker-dek").exists():
                raise RuntimeError("Installation left a plaintext working DEK file")
            credential_binding(root, key_path)
            print("Worker container reached scoped IPC; Backend had neither privilege socket nor runtime credential mount.", flush=True)
            time_code = """import json
from hostorbit.runtime.authority import verify_host_time
from hostorbit.runtime.ipc import Client
c=json.load(open('/etc/hostorbit/runtime.json'))
envelope=Client(c['gate_socket'],server_uids={0}).call('time.health',{})
report=verify_host_time(envelope,open(c['public_verify_key'],'rb').read())
assert report['type']=='time.health' and report['state'] in ('FRESH','HOLDOVER','UNTRUSTED')
print('VERIFIED_HOST_TIME')
"""
            if docker(args.docker_host, "exec", ids["worker"], "python", "-c", time_code) != "VERIFIED_HOST_TIME":
                raise RuntimeError("Container Worker could not verify the host TimeHealth signature")
            print("Networkless Worker verified host TimeHealth through authenticated IPC and the mounted public key.", flush=True)
            with tls_proxy(root) as context:
                def request(path, body=None):
                    request = Request(ORIGIN + path, data=None if body is None else json.dumps(body).encode(),
                                      headers={"Origin": ORIGIN, "Content-Type": "application/json"})
                    try:
                        return urlopen(request, context=context, timeout=10)
                    except urllib.error.HTTPError as error:
                        return error
                before = request("/api/v1/users", {"username": "visitor", "password": PASSWORD, "role": "Owner"})
                if before.status not in (401, 422):
                    raise RuntimeError("Anonymous visitor could provision an administrator")
                with sqlite3.connect("/var/lib/hostorbit/app/controller.sqlite3") as db:
                    if db.execute("SELECT count(*) FROM users").fetchone() != (0,):
                        raise RuntimeError("Installation unexpectedly created an Owner")
                owner_create()
                login = request("/api/v1/auth/login", {"username": "roman", "password": PASSWORD})
                if login.status != 200 or "Secure" not in login.headers.get("Set-Cookie", ""):
                    raise RuntimeError("Installed Owner could not authenticate through HTTPS proxy")
                login.close()
            print("First web visitor had no bootstrap authority; hidden-input local Owner setup and HTTPS login passed.", flush=True)
            writer_barrier(args.docker_host, ids)
            vault_pin()
            local_archive, fixture_identity = controller_archive(root, args.bundle)
            import base64
            rescue_input = json.dumps({"archive": local_archive, "identity": base64.b64encode(fixture_identity).decode(),
                "anchor": str(root / "independent-controller.pub"), "password": PASSWORD,
                "keygen": str(args.bundle.parent / "hostorbit-install-age/age/age-keygen")}).encode()
            recovered = run("/opt/hostorbit/venv/bin/python", "tests_runtime/lab/rescue.py", "--isolated-vm", "--keep-data", input=rescue_input, timeout=120)
            print(recovered.stdout.decode().strip(), flush=True)
            del rescue_input
            sftp_publication(root, local_archive, fixture_identity)
            migration_rehearsal(root)
            before = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/hostorbit/credentials/broker-dek.cred"),
                ("gate", "/var/lib/hostorbit/control-gate/signing.key"))}
            again = run(*base, check=False, timeout=30)
            if again.returncode == 0:
                raise RuntimeError("Second install replaced a live installation")
            after = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/hostorbit/credentials/broker-dek.cred"),
                ("gate", "/var/lib/hostorbit/control-gate/signing.key"))}
            if before != after:
                raise RuntimeError("Second install changed private keys")
            run("/usr/bin/systemctl", "stop", "hostorbit-compose.service", timeout=80)
            stopped = json.loads(docker(args.docker_host, "inspect", ids["worker"]))[0]["State"]
            if stopped["Running"] or stopped["ExitCode"] != 0 or stopped["OOMKilled"]:
                raise RuntimeError("Idle Worker did not handle SIGTERM and exit cleanly")
            print("Container PID 1 Worker handled SIGTERM, released its lock and exited with code 0.", flush=True)
            run("/usr/bin/systemctl", "start", "hostorbit-compose.service", timeout=150)
            if json.load(urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=5))["status"] != "alive":
                raise RuntimeError("Compose service did not recover after restart")
            print("Repeated install was denied without key replacement; systemd Compose restart preserved the installation.", flush=True)
            recovery_installation(args, base, foreign)
        except Exception:
            for service in ("hostorbit-vault-initialize.service", "hostorbit-broker.service", "hostorbit-supervisor.service", "hostorbit-compose.service"):
                result = run("/usr/bin/journalctl", "--unit", service, "--no-pager", "--lines", "40", check=False)
                print(result.stdout.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            foreign.close()
            # This job owns the entire disposable VM. Preserve failed install
            # state/logs until the runner is discarded; never wipe a user VPS.
            if installed and Path("/etc/hostorbit/compose.json").exists():
                run("/usr/bin/systemctl", "stop", "hostorbit-compose.service", check=False, timeout=80)
                docker(args.docker_host, "compose", "--project-name", "hostorbit", "--file",
                       "/etc/hostorbit/compose.json", "down", timeout=60)
            run("/usr/bin/umount", daemon_socket, check=False)
            if Path("/var/lib/hostorbit-rescue-lab").exists():
                shutil.rmtree("/var/lib/hostorbit-rescue-lab")
            Path("/opt").chmod(opt_mode)


if __name__ == "__main__":
    main()
