#!/usr/bin/env python3
"""K-VPN Monitor panel-side state evaluator (stdlib only)."""
import argparse
import fcntl
import json
import os
import pathlib
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_CONFIG = '/etc/kvpn-monitor/config.json'


def save_atomic(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_status(path):
    try:
        line = pathlib.Path(path).read_text().strip().split()
        if len(line) != 2 or line[1] not in ('OK', 'FAIL'):
            return None
        return (int(line[0]), line[1])
    except (OSError, ValueError):
        return None


def evaluate(probe, old, sample, now):
    """Return (new_state, event_or_None), once per new timestamp."""
    state = dict(old or {})
    state.setdefault('state', 'INIT')
    state.setdefault('last_timestamp', 0)
    state.setdefault('fails', 0)
    state.setdefault('successes', 0)
    stale_after = int(probe.get('stale_after', 720))
    fail_threshold = int(probe.get('fail_threshold', 2))
    recovery_threshold = int(probe.get('recovery_threshold', 1))
    if min(stale_after, fail_threshold, recovery_threshold) < 1:
        raise ValueError('thresholds must be positive')

    timestamp, status = sample if sample is not None else (0, 'UNKNOWN')
    # A slightly future timestamp indicates clock skew or corrupted file.
    unknown = status == 'UNKNOWN' or timestamp > now + 10 or now - timestamp > stale_after
    event = None
    if unknown:
        state['fails'] = 0
        state['successes'] = 0
        if state['state'] not in ('INIT', 'UNKNOWN'):
            state['state'] = 'UNKNOWN'
            event = 'UNKNOWN'
    elif timestamp > state['last_timestamp']:
        state['last_timestamp'] = timestamp
        if status == 'FAIL':
            state['fails'] += 1
            state['successes'] = 0
            if state['fails'] >= fail_threshold and state['state'] != 'FAIL':
                state['state'] = 'FAIL'
                event = 'FAIL'
        else:
            state['successes'] += 1
            state['fails'] = 0
            if state['state'] == 'INIT':
                state['state'] = 'OK'
            elif state['state'] in ('FAIL', 'UNKNOWN') and state['successes'] >= recovery_threshold:
                state['state'] = 'OK'
                event = 'RECOVERED'
    # No startup spam: a nonexistent probe does not alert until it has checked in.
    return state, event


def send_telegram(token, chat_id, thread_id, message):
    data = urllib.parse.urlencode({'chat_id': str(chat_id), 'message_thread_id': str(thread_id), 'text': message}).encode()
    req = urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=data, method='POST')
    with urllib.request.urlopen(req, timeout=15) as response:
        payload = json.load(response)
    if not payload.get('ok'):
        raise RuntimeError('Telegram API rejected message')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test-telegram', action='store_true', help='Send an explicit test message; do not change monitor states')
    args = parser.parse_args()
    config = json.loads(pathlib.Path(args.config).read_text())
    if args.test_telegram:
        token = pathlib.Path(config['token_file']).read_text().strip()
        send_telegram(token, config['chat_id'], config['thread_id'], '🧪 K-VPN Monitor: тестовое уведомление. Настройки Telegram работают.')
        print('Telegram test message delivered')
        return
    root = pathlib.Path(config.get('state_dir', '/var/lib/kvpn-monitor'))
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / '.monitor.lock'
    with open(lock_path, 'a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        now = int(time.time())
        state_path = root / 'state.json'
        try:
            old_states = json.loads(state_path.read_text())
        except (OSError, ValueError):
            old_states = {}
        new_states = dict(old_states)
        events = []
        for probe in config['probes']:
            pid = probe['id']
            sample = read_status(root / 'reports' / (pid + '.status'))
            new, event = evaluate(probe, old_states.get(pid), sample, now)
            new_states[pid] = new
            age = now - sample[0] if sample else None
            print(f"{pid}: {new['state']} (last={sample[1] if sample else 'NONE'}, age={age}s)")
            if event:
                messages = {
                    'FAIL': f"🔴 K-VPN Monitor: {probe['name']}\n\nПроверка завершилась ошибкой несколько раз подряд.\nИсточник: {pid}",
                    'UNKNOWN': f"🟠 K-VPN Monitor: {probe['name']}\n\nНет свежих отчётов. Состояние неизвестно.\nИсточник: {pid}",
                    'RECOVERED': f"🟢 K-VPN Monitor: {probe['name']}\n\nДоступность восстановлена.\nИсточник: {pid}",
                }
                events.append((pid, event, messages[event]))
        if args.dry_run:
            for pid, event, _ in events:
                print('DRY RUN:', pid, event)
            return
        # Persist event to outbox *before* sending. On transport uncertainty retries
        # may duplicate a Telegram message; no Telegram-side idempotency key exists.
        # Outbox survives delivery failures; a crash during delivery can still duplicate an alert.
        outbox_dir = root / 'outbox'
        outbox_dir.mkdir(parents=True, exist_ok=True)
        for pid, event, msg in events:
            item = {'probe': pid, 'event': event, 'text': msg, 'time': now}
            # Unique event filenames preserve incident history across Telegram outages.
            # A future event cannot overwrite a still-pending earlier event.
            filename = f'{pid}-{now}-{event}.json'
            save_atomic(outbox_dir / filename, item)
        save_atomic(state_path, new_states)
        token = pathlib.Path(config['token_file']).read_text().strip()
        for itempath in sorted(outbox_dir.glob('*.json')):
            item = json.loads(itempath.read_text())
            try:
                send_telegram(token, config['chat_id'], config['thread_id'], item['text'])
            except (OSError, RuntimeError, urllib.error.URLError) as exc:
                print('Telegram failed:', itempath.name, type(exc).__name__, file=sys.stderr)
                continue
            # Do not erase an alert replaced by another process (lock guards monitor only)
            itempath.unlink()
            print('Telegram delivered:', item['probe'], item['event'])


if __name__ == '__main__':
    main()
