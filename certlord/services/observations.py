"""Read-only certificate facts for external supervision; no alert thresholds."""
from datetime import datetime, timezone
from certlord.services.verification import verification_metadata
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from certlord.services.certificate_ids import require_certificate_id


STATES = frozenset(('create', 'exists', 'invalid-dns', 'delete', 'renew',
                    'processing', 'generated', 'deployed'))


def certificate_observation(certificate_id, domain, record, version, pending):
    """Project an allowlist from one Vault version and a separate Redis read."""
    certificate_id = require_certificate_id(certificate_id)
    if type(version) is not int or version <= 0:
        raise ValueError('Invalid observation version')
    origin = record.get('origin')
    if origin not in ('external', 'acme', 'provider-managed'):
        origin = 'acme' if record.get('vendor') == 'letsencrypt' else 'unknown'
    owner = record.get('renewal_owner')
    if owner not in ('external', 'acme', 'provider-managed'):
        owner = origin
    action = pending.get('status')
    if action not in STATES:
        action = 'unknown' if action is not None else 'none'
    retry = None
    last_retry = None
    if owner == 'acme' and action in ('create', 'renew'):
        retry = pending.get('retry', 0)
        if type(retry) is not int or retry < 0:
            raise ValueError('Invalid pending retry count')
        if pending.get('last_retry'):
            last_retry = datetime.strptime(pending['last_retry'], '%Y-%m-%d %H:%M:%S').replace(
                tzinfo=timezone.utc).isoformat()
    result = dict(certificate_id=certificate_id, domains=[domain], version=version,
                  status=record.get('status') if record.get('status') in STATES else 'unknown',
                  origin=origin, renewal_owner=owner, pending_action=action,
                  issuance_retry_count=retry, last_issuance_retry_at=last_retry,
                  material_state='missing', not_before=None, not_after=None,
                  not_after_timestamp_seconds=None, fingerprint_sha256=None)
    pem = record.get('cert')
    if pem:
        try:
            if not isinstance(pem, str) or len(pem) > 65536:
                raise ValueError('Invalid certificate material')
            leaf = x509.load_pem_x509_certificate(pem.encode('ascii'))
            result.update(material_state='readable', not_before=leaf.not_valid_before_utc.isoformat(),
                          not_after=leaf.not_valid_after_utc.isoformat(),
                          not_after_timestamp_seconds=leaf.not_valid_after_utc.timestamp(),
                          fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex())
        except (ValueError, TypeError, UnicodeError):
            result['material_state'] = 'invalid'
    result['verification'] = verification_metadata(record)
    result['observed_at'] = datetime.now(timezone.utc).isoformat()
    return result


def prometheus_metrics(observation):
    """Prometheus text 0.0.4; labels have fixed names and allowlisted values."""
    lines = []

    def family(name, help_text):
        lines.extend(('# HELP ' + name + ' ' + help_text, '# TYPE ' + name + ' gauge'))

    def sample(name, value, **labels):
        suffix = '{' + ','.join(key + '=' + json.dumps(value) for key, value in labels.items()) + '}' if labels else ''
        lines.append('%s%s %s' % (name, suffix, value))

    family('certlord_observation_completed_timestamp_seconds', 'Completion time of this successful collection, Unix seconds.')
    sample('certlord_observation_completed_timestamp_seconds', observation['completed_timestamp_seconds'])
    family('certlord_certificates_observed', 'Certificates included in this collection.')
    sample('certlord_certificates_observed', len(observation['certificates']))
    family('certlord_certificate_info', 'Stored lifecycle metadata; not a served TLS verification.')
    for record in observation['certificates']:
        sample('certlord_certificate_info', 1, **{name: record[name] for name in
               ('certificate_id', 'origin', 'renewal_owner', 'status', 'pending_action', 'material_state')})
    family('certlord_certificate_not_after_timestamp_seconds', 'Stored leaf expiry, Unix seconds; absent for missing or invalid PEM.')
    for record in observation['certificates']:
        if record['not_after_timestamp_seconds'] is not None:
            sample('certlord_certificate_not_after_timestamp_seconds', record['not_after_timestamp_seconds'],
                   certificate_id=record['certificate_id'])
    family('certlord_certificate_issuance_retry_count', 'Retries for currently pending ACME creation or renewal; not a lifetime counter.')
    for record in observation['certificates']:
        if record['issuance_retry_count'] is not None:
            sample('certlord_certificate_issuance_retry_count', record['issuance_retry_count'],
                   certificate_id=record['certificate_id'])
    family('certlord_certificate_tls_verification', 'Last recorded deployment TLS result; not continuous monitoring.')
    for record in observation['certificates']:
        verification = record['verification']
        sample('certlord_certificate_tls_verification', 1, certificate_id=record['certificate_id'],
               status=verification['status'] if verification else 'not_checked')
    family('certlord_certificate_tls_verified_at_timestamp_seconds', 'Time of the last recorded successful deployment TLS check.')
    for record in observation['certificates']:
        verification = record['verification']
        if verification and verification['status'] == 'verified':
            sample('certlord_certificate_tls_verified_at_timestamp_seconds',
                   datetime.fromisoformat(verification['checked_at']).timestamp(),
                   certificate_id=record['certificate_id'])
    return '\n'.join(lines) + '\n'


def operations_metrics(observation):
    """Current work gauges, not lifetime throughput counters."""
    lines = []
    def gauge(name, help_text, value):
        lines.extend(('# HELP ' + name + ' ' + help_text, '# TYPE ' + name + ' gauge'))
        if value is not None:
            lines.append(name + ' ' + str(value))
    for field, description in (
        ('deployment_entries', 'Observed pending deployment entries.'),
        ('deployment_missing_timestamps', 'Queue entries without enqueue timestamps.'),
        ('deployment_oldest_age_seconds', 'Age of the oldest observed enqueue timestamp.'),
        ('pending_retry_count', 'Sum of current create, renew and delete retries.'),
        ('pending_at_retry_limit', 'Pending actions at or above configured retry limit.'),
        ('deployment_lease_ttl_seconds', 'Remaining deployment lease TTL, when expiring.'),
        ('completed_timestamp_seconds', 'Completion time of this operations observation.')):
        gauge('certlord_operations_' + field, description, observation[field])
    lines.extend(('# HELP certlord_pending_actions Observed Redis pending actions by state.',
                  '# TYPE certlord_pending_actions gauge'))
    for state, count in observation['pending_actions'].items():
        lines.append('certlord_pending_actions{state=' + json.dumps(state) + '} ' + str(count))
    lines.extend(('# HELP certlord_deployment_lease_state Current lease presence, never its owner token.',
                  '# TYPE certlord_deployment_lease_state gauge',
                  'certlord_deployment_lease_state{state=' + json.dumps(observation['deployment_lease_state']) + '} 1'))
    cycles = observation.get('cycles')
    if cycles is not None:
        for field, description in (
                ('running', 'Current process cycle is executing; not an assertion of forward progress.'),
                ('persisted', 'Last local cycle event was acknowledged by Redis.'),
                ('started_timestamp_seconds', 'Start time of the last local cycle.'),
                ('finished_timestamp_seconds', 'End time of the last local cycle, when known.'),
                ('duration_seconds', 'Duration of the last local completed cycle, not operation success.')):
            name = 'certlord_worker_cycle_' + field
            lines.extend(('# HELP ' + name + ' ' + description, '# TYPE ' + name + ' gauge'))
            for worker, record in cycles['local'].items():
                value = int(record['state'] == 'running') if field == 'running' else record[field]
                if value is not None:
                    lines.append(name + '{worker=' + json.dumps(worker) + '} ' + str(int(value) if isinstance(value, bool) else value))
    return '\n'.join(lines) + '\n'
