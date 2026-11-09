"""Scoped, bounded read model over registered resources and completed probes."""

import json
import re
import time

from .auth import AuthService, Role, etag
from .errors import Denied
from .queue import JobQueue
from .runtime.protocol import SHA256, ULID, checksum, docker_summary, software_summary


_SELECT = """
SELECT r.*, j.status AS job_status, j.reason AS job_reason, j.updated_at AS checked_at,
       j.scope_digest AS job_scope, j.policy_revision AS job_policy, j.result AS job_result,
       s.result AS success_result
FROM resources r
LEFT JOIN jobs j ON j.id=(
    SELECT candidate.id FROM audit a JOIN jobs candidate ON candidate.id=a.correlation_id
    WHERE a.target_id=r.id AND candidate.resource_id=r.id
    AND candidate.status IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')
    AND (a.event='job.finished' OR (a.event='job.accepted' AND candidate.reason='RESTORE_QUARANTINE'))
    ORDER BY a.seq DESC LIMIT 1)
LEFT JOIN jobs s ON s.id=(
    SELECT candidate.id FROM audit a JOIN jobs candidate ON candidate.id=a.correlation_id
    WHERE a.target_id=r.id AND a.event='job.finished' AND candidate.resource_id=r.id
    AND candidate.status='SUCCEEDED' AND candidate.scope_digest=r.scope_digest
    AND candidate.policy_revision=r.policy_revision
    ORDER BY a.seq DESC LIMIT 1)
WHERE r.id>? AND (? IS NULL OR r.id=?)
AND (? OR EXISTS (SELECT 1 FROM grants g WHERE g.user_id=?
                 AND g.permission='vps:read' AND g.resource_id IN (r.id,'*')))
ORDER BY r.id LIMIT ?
"""


def _sample(raw):
    if raw is None:
        return None
    try:
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('status') != 'REACHABLE'
                or value.get('source') != 'restricted_helper' or type(value.get('observed_at')) is not int
                or not isinstance(value.get('boot_id'), str)
                or not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id'])):
            return None
        sample = {k: value[k] for k in ('status', 'source', 'observed_at', 'boot_id')}
        if 'software' in value:
            sample['software'] = software_summary(value['software'])
        if 'docker' in value:
            if 'software' not in sample:
                return None
            sample['docker'] = docker_summary(value['docker'])
        return sample
    except (ValueError, TypeError, Denied):
        return None


class Inventory:
    def __init__(self, store, *, clock=time.time):
        self.store, self.clock = store, clock

    def _public(self, row, now):
        success = _sample(row['success_result'])
        status, reason = 'NOT_CHECKED', 'NO_COMPLETED_OBSERVATION'
        if row['job_status'] is not None:
            status = 'UNKNOWN'
            if row['job_scope'] != row['scope_digest'] or row['job_policy'] != row['policy_revision']:
                reason = 'OBSERVATION_SCOPE_CHANGED'
            elif row['job_status'] != 'SUCCEEDED':
                reason = row['job_reason']
            else:
                sample = _sample(row['job_result'])
                if sample is None:
                    reason = 'OBSERVATION_INVALID'
                elif sample['observed_at'] > now or row['checked_at'] > now:
                    reason = 'OBSERVATION_TIME_INVALID'
                elif now - sample['observed_at'] > 300:
                    reason = 'OBSERVATION_STALE'
                else:
                    status, reason = 'REACHABLE', 'PROBE_SUCCEEDED'
        if not row['enabled']:
            status, reason = 'UNKNOWN', 'RESOURCE_DISABLED'
        return {**{k: row[k] for k in ('id', 'revision', 'policy_revision', 'created_at', 'updated_at')},
                'enabled': bool(row['enabled']), 'access_mode': 'READ_ONLY',
                'observation': {'status': status, 'reason': reason,
                                'last_checked_at': row['checked_at'], 'last_success': success}}

    def _rows(self, auth, token, *, after='', identity=None, limit=51, permission=None):
        with self.store.read() as db:
            JobQueue._schema(db)
            actor = auth._session(db, token)
            rows = db.execute(_SELECT, (after, identity, identity, actor['role'] == Role.OWNER,
                                        actor['id'], limit)).fetchall()
            now = int(self.clock())
            for row in rows:
                AuthService.require(db, actor, 'vps:read', row['id'])
                if permission is not None:
                    AuthService.require(db, actor, permission, row['id'])
            return [self._public(row, now) for row in rows]

    def list(self, auth, token, *, after='', limit=50):
        if type(limit) is not int or not 1 <= limit <= 100 or (after and re.fullmatch(ULID, after) is None):
            raise Denied('INVENTORY_CURSOR_INVALID', 422)
        rows = self._rows(auth, token, after=after, limit=limit + 1)
        value = {'items': rows[:limit], 'next_after': rows[limit - 1]['id'] if len(rows) > limit else None}
        return value, etag(value, 0)

    def _resource(self, auth, token, identity, *, permission=None):
        if re.fullmatch(ULID, identity) is None:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        rows = self._rows(auth, token, identity=identity, limit=1, permission=permission)
        if not rows:
            raise Denied('RESOURCE_NOT_FOUND', 404)
        return rows[0]

    def get(self, auth, token, identity):
        value = self._resource(auth, token, identity)
        return value, etag(value, value['revision'])

    def restart_preview(self, auth, token, identity, container_id):
        if re.fullmatch(SHA256, container_id) is None:
            raise Denied('CONTAINER_NOT_FOUND', 404)
        resource = self._resource(auth, token, identity, permission='vps:restart')
        observation = resource['observation']
        if observation['status'] != 'REACHABLE':
            raise Denied('FRESH_OBSERVATION_REQUIRED', 409)
        sample = observation['last_success']
        docker = sample.get('docker') if sample else None
        if docker is None or docker['status'] != 'OBSERVED':
            raise Denied('DOCKER_OBSERVATION_REQUIRED', 409)
        container = next((item for item in docker['containers'] if item['id'] == container_id), None)
        if container is None:
            raise Denied('CONTAINER_NOT_FOUND', 404)
        if container['state'] != 'RUNNING':
            raise Denied('CONTAINER_NOT_RUNNING', 409)
        preview = {
            'version': 1,
            'action': 'docker.restart',
            'status': 'PREVIEW_ONLY',
            'target': {'resource_id': identity, **container},
            'resource_revision': resource['revision'],
            'policy_revision': resource['policy_revision'],
            'observed_at': sample['observed_at'],
            'boot_id': sample['boot_id'],
            'risk': 'TEMPORARY_SERVICE_INTERRUPTION',
        }
        return {**preview, 'preview_digest': checksum(preview)}
