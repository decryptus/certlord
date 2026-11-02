"""Version-bound destination state and orchestration over injected adapters."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from certlord.ports.certificates import StorageConflict
from certlord.services.verification import verification_metadata

DESTINATION_NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}')
STATES = frozenset(('pending', 'submitting', 'uncertain', 'failed', 'verifying', 'verified'))
ERRORS = frozenset(('command_failed', 'command_uncertain', 'tls_failed'))
MAX_DESTINATIONS = 32


def certificate_generation(certificate):
    material = [certificate.get('cert', ''), certificate.get('chain', '')]
    return hashlib.sha256(json.dumps(material, separators=(',', ':')).encode('utf-8')).hexdigest()


def destination_state(record, targets):
    generation = certificate_generation(record)
    previous = record.get('deployment', {})
    if not isinstance(previous, dict) or previous.get('generation') != generation:
        previous = {}
    entries = previous.get('destinations', {})
    if not isinstance(entries, dict):
        entries = {}
    result = {'generation': generation, 'destinations': {}}
    for name, target in targets.items():
        old = entries.get(name, {})
        if (not isinstance(old, dict) or old.get('target_sha256') != target
                or old.get('status') not in STATES):
            old = {'status': 'pending', 'target_sha256': target}
        result['destinations'][name] = copy.deepcopy(old)
    return result


def complete(state):
    entries = state['destinations']
    return bool(entries) and all(e['status'] == 'verified' for e in entries.values())


def deployment_metadata(record, targets):
    state = destination_state(record, targets)
    entries = []
    for name, data in state['destinations'].items():
        entry = {'name': name, 'status': data['status'], 'target_sha256': data['target_sha256'],
                 'error_code': data.get('error_code') if data.get('error_code') in ERRORS else None,
                 'verification': verification_metadata({'verification': data.get('verification')})}
        if isinstance(data.get('attempt_id'), str) and re.fullmatch(r'[0-9a-f-]{36}', data['attempt_id']):
            entry['attempt_id'] = data['attempt_id']
        entries.append(entry)
    succeeded = sum(e['status'] == 'verified' for e in entries)
    status = ('verified' if complete(state) else 'partial' if succeeded else
              'uncertain' if any(e['status'] in ('uncertain', 'submitting') for e in entries) else
              'failed' if any(e['status'] == 'failed' for e in entries) else 'pending')
    try:
        fingerprint = x509.load_pem_x509_certificate(record['cert'].encode('ascii')).fingerprint(hashes.SHA256()).hex()
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError):
        fingerprint = None
    return {'generation': state['generation'], 'expected_fingerprint_sha256': fingerprint,
            'status': status, 'verified': succeeded,
            'total': len(entries), 'destinations': entries}


class DestinationDeployment:
    """Persist submission intent before effects; resume the same job after restart.

    read/write are versioned storage callbacks; command and verify are adapters.
    An ambiguous storage write or stale certificate aborts this cycle. No retry of
    an external command is inferred from its absence or a transport failure.
    """
    def __init__(self, read, write, command, verify, guard):
        self.read, self.write = read, write
        self.command, self.verify, self.guard = command, verify, guard

    def run(self, identity, domain, snapshot, targets):
        generation = certificate_generation(snapshot[0])

        def current():
            value = self.read(identity, domain)
            if (certificate_generation(value[0]) != generation
                    or value[0].get('status') not in ('generated', 'deployed', '', None)):
                raise StorageConflict('Certificate changed during destination deployment')
            return value

        def persist(value, state):
            self.guard()
            self.write(identity, domain, value, state)

        for name in targets:
            self.guard()
            value = current()
            state = destination_state(value[0], targets)
            entry = state['destinations'][name]
            if entry['status'] == 'verified':
                continue
            if entry['status'] == 'failed' and not entry.get('command_succeeded'):
                continue
            if not entry.get('command_succeeded'):
                submit = entry['status'] == 'pending'
                if submit:
                    entry.update(status='submitting', attempt_id=str(uuid4()), error_code=None)
                    persist(value, state)
                    value = current()
                    # A concurrent explicit retry must not authorize this old intent.
                    if destination_state(value[0], targets) != state:
                        raise StorageConflict('Destination changed before command launch')
                self.guard()
                try:
                    success = self.command(identity, domain, name, generation,
                                           entry['attempt_id'], submit)
                except Exception:
                    entry.update(status='uncertain', error_code='command_uncertain')
                    persist(value, state)
                    continue
                entry.update(status='verifying' if success else 'failed',
                             command_succeeded=bool(success),
                             error_code=None if success else 'command_failed')
                persist(value, state)
                if not success:
                    continue
                value = current()
                if destination_state(value[0], targets) != state:
                    raise StorageConflict('Destination changed before TLS verification')
            self.guard()
            verification = self.verify(identity, domain, name, value[0])
            entry.update(verification=verification,
                         status='verified' if verification['status'] == 'verified' else 'failed',
                         error_code=None if verification['status'] == 'verified' else 'tls_failed',
                         updated_at=datetime.now(timezone.utc).isoformat())
            persist(value, state)
        final = current()
        state = destination_state(final[0], targets)
        if complete(state) and final[0].get('status') != 'deployed':
            persist(final, state)
        return complete(state)
