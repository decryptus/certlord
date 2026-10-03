"""Allowlisted historical TLS verification metadata, without infrastructure details."""
from datetime import datetime, timezone
import re

ERROR_CODES = frozenset(('fingerprint_mismatch', 'tls_validation_failed', 'timeout',
                         'tls_handshake_failed', 'connection_or_trust_store_failed',
                         'probe_failed', 'invalid_stored_certificate'))


def verification_metadata(record):
    data = record.get('verification')
    if not isinstance(data, dict) or data.get('status') not in ('verified', 'failed'):
        return None
    try:
        checked = datetime.fromisoformat(data['checked_at'])
        if checked.tzinfo is None:
            return None
    except (KeyError, ValueError, TypeError):
        return None
    result = {'status': data['status'], 'checked_at': checked.astimezone(timezone.utc).isoformat(),
              'error_code': data.get('error_code') if data.get('error_code') in ERROR_CODES else None}
    for field in ('expected_fingerprint_sha256', 'observed_fingerprint_sha256', 'target_sha256'):
        value = data.get(field)
        result[field] = value if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) else None
    return result
