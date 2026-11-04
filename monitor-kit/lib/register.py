#!/usr/bin/env python3
"""Atomically register one K-VPN monitor probe and its SSH authorization.

Registration can be retried if interrupted: duplicate exact public keys are not
appended and completed registrations are no-ops. Never log secret material.
"""
import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile

DEFAULT_CONFIG = Path('/etc/kvpn-monitor/config.json')
DEFAULT_AUTH = Path('/home/kvpn-probe/.ssh/authorized_keys')


def write_atomic(path, text, mode, uid, gid):
    fd, name = tempfile.mkstemp(prefix='.kvpn-reg-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as file:
            os.fchmod(file.fileno(), mode)
            os.fchown(file.fileno(), uid, gid)
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def register(config_path, auth_path, pid, name, pub, source, stale, fail, recovery):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,39}', pid):
        raise ValueError('Invalid probe ID')
    if not name or len(name) > 100 or '\n' in name:
        raise ValueError('Invalid label')
    try:
        ipaddress.ip_address(source)
    except ValueError as exc:
        raise ValueError('Invalid source IP') from exc
    for value in (stale, fail, recovery):
        if value < 1:
            raise ValueError('Thresholds must be positive')
    if any(ch in pub for ch in ('\r', '\n', '\x00')):
        raise ValueError('Public SSH key must be on one line')
    parts = pub.split()
    if len(parts) not in (2, 3) or parts[0] != 'ssh-ed25519':
        raise ValueError('Only single-line Ed25519 public keys are accepted')
    try:
        key_bytes = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError('Invalid public key') from exc
    key_fp = 'SHA256:' + base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip('=')
    entry = f'from="{source}",restrict,command="/usr/bin/python3 /opt/kvpn-monitor/receiver.py {pid}" {pub}'

    lock_path = config_path.parent / '.register.lock'
    with lock_path.open('a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        config = json.loads(config_path.read_text())
        probes = config['probes']
        previous = next((p for p in probes if p['id'] == pid), None)
        old_auth = auth_path.read_text()
        current_lines = old_auth.splitlines()
        # The same key must not be reused with a different forced command/ID:
        # sshd may pick the first matching authorized_keys entry.
        if any(len(line.split()) >= 2 and parts[1] in line.split() and
               line != entry for line in current_lines):
            raise ValueError('Public key is already present for another authorization')
        # Other credentials must not be authorized to submit to the same ID.
        receiver_tag = f'/opt/kvpn-monitor/receiver.py {pid}"'
        conflicting = [line for line in current_lines if receiver_tag in line and line != entry]
        if conflicting:
            raise ValueError('Probe ID is already bound to a different SSH key or source')
        if previous:
            if previous.get('source_ip') != source or previous.get('key_sha256') != key_fp:
                raise ValueError('Probe ID already registered with different metadata')
            if entry in current_lines:
                print('Probe already registered; nothing changed:', pid)
                return
        if entry in current_lines and not previous:
            print('Recovering interrupted registration for', pid)
        new_auth = old_auth if entry in current_lines else (old_auth.rstrip('\n') + '\n' if old_auth else '') + entry + '\n'
        new_conf = dict(config)
        if not previous:
            new_conf['probes'] = probes + [{
                'id': pid, 'name': name, 'stale_after': stale, 'fail_threshold': fail,
                'recovery_threshold': recovery, 'source_ip': source, 'key_sha256': key_fp,
            }]
        a = auth_path.stat()
        c = config_path.stat()
        # Write key first: a crash before config update is recoverable by retry.
        if new_auth != old_auth:
            write_atomic(auth_path, new_auth, 0o600, a.st_uid, a.st_gid)
        try:
            write_atomic(config_path, json.dumps(new_conf, ensure_ascii=False, indent=2) + '\n',
                         0o600, c.st_uid, c.st_gid)
        except Exception:
            # If config update fails, remove authorization granted in this call.
            if new_auth != old_auth:
                write_atomic(auth_path, old_auth, 0o600, a.st_uid, a.st_gid)
            raise
    print('Registered', pid)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('pid')
    p.add_argument('label')
    p.add_argument('pub')
    p.add_argument('source')
    p.add_argument('stale', type=int)
    p.add_argument('fail', type=int)
    p.add_argument('recovery', type=int)
    p.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    p.add_argument('--authorized-keys', type=Path, default=DEFAULT_AUTH)
    a = p.parse_args()
    register(a.config, a.authorized_keys, a.pid, a.label, a.pub, a.source,
             a.stale, a.fail, a.recovery)


if __name__ == '__main__':
    main()
