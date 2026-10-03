"""Canonical certificate identities and human-facing selectors."""
import re
from uuid import UUID
from certlord.classes.config import CERTIFICATE_ID_PATTERN


def valid_certificate_id(value):
    if not isinstance(value, str) or re.fullmatch(CERTIFICATE_ID_PATTERN, value) is None:
        return False
    parsed = UUID(value)
    return parsed.variant == 'specified in RFC 4122' and parsed.version in (1, 3, 4, 5, 6, 7, 8)


def require_certificate_id(value):
    if not valid_certificate_id(value):
        raise ValueError('certificate_id must be a canonical lowercase UUID')
    return value


def resolve_certificate(selector, records):
    """Resolve a full UUID, exact domain or UUID prefix; never choose a first match."""
    value = selector.lower()
    prefix = re.fullmatch(r'[0-9a-f]{8}[0-9a-f-]*', value) is not None
    matches = {record['certificate_id'] for record in records
               if record['certificate_id'] == value
               or value in record['domains']
               or (prefix and record['certificate_id'].startswith(value))}
    if not matches:
        raise ValueError('No certificate matches this selector')
    if len(matches) != 1:
        raise ValueError('Ambiguous selector; use a longer prefix or the full UUID')
    return matches.pop()


def short_ids(records):
    """Lengthen display prefixes until unique within this inventory."""
    identities = [record['certificate_id'] for record in records]
    return {value: next((value[:size] for size in range(8, 37)
                        if sum(other.startswith(value[:size]) for other in identities) == 1), value)
            for value in identities}
