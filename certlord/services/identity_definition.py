"""Versioned canonical certificate identity; never contains keys or credentials."""
import hashlib
import json
import re


IDENTITY_VERSION = 1
DOMAIN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def identity_definition(domains):
    if not isinstance(domains, (list, tuple)) or not domains:
        raise ValueError('At least one domain is required')
    normalized = set()
    for domain in domains:
        if not isinstance(domain, str):
            raise ValueError('Invalid certificate domain')
        # Domain identity is ASCII A-label form, lowercase, without a root dot.
        value = domain.lower().removesuffix('.').encode('idna').decode('ascii')
        labels = value.split('.')
        if len(value) > 253 or len(labels) < 2 or any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError('Invalid certificate domain')
        normalized.add(value)
    return {'version': IDENTITY_VERSION, 'domains': sorted(normalized)}


def identity_fingerprint(definition):
    expected = identity_definition(definition['domains'])
    if definition != expected:
        raise ValueError('Noncanonical certificate identity')
    canonical = json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
