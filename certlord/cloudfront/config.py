"""Immutable job profile, bound to an explicit Auton endpoint revision."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from certlord.cloudfront.preflight import validate_plan
from certlord.services.certificate_ids import require_certificate_id


class JobError(Exception):
    """Messages are fixed public error codes, never provider exception text."""


def require(condition, code):
    if not condition:
        raise JobError(code)


def validate_profile(profile):
    required = {'target', 'certificate_id', 'destination', 'vault', 'state_dir',
                'poll_interval', 'propagation_timeout'}
    require(isinstance(profile, dict) and required <= set(profile)
            and not set(profile) - required - {'aws_profile'}, 'invalid_profile')
    validate_plan(profile['target'])
    require_certificate_id(profile['certificate_id'])
    require(isinstance(profile['destination'], str)
            and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile['destination']), 'invalid_destination')
    for field, low, high in (('poll_interval', 1, 300), ('propagation_timeout', 5, 172800)):
        value = profile[field]
        require(type(value) in (int, float) and low <= value <= high, 'invalid_deadline')
    require(profile['poll_interval'] < profile['propagation_timeout'], 'invalid_deadline')
    require(isinstance(profile['state_dir'], str) and Path(profile['state_dir']).is_absolute(), 'invalid_state_dir')
    vault = profile['vault']
    require(isinstance(vault, dict) and set(vault) ==
            {'url', 'mount', 'key_name', 'role_id_file', 'secret_id_file', 'ca_file'}, 'invalid_vault_profile')
    url = urlsplit(vault['url'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and url.path in ('', '/') and not url.query and not url.fragment, 'vault_requires_https')
    for field in ('mount', 'key_name'):
        require(isinstance(vault[field], str) and re.fullmatch(r'[a-zA-Z0-9_-]+', vault[field]), 'invalid_vault_path')
    for field in ('role_id_file', 'secret_id_file'):
        require(isinstance(vault[field], str) and Path(vault[field]).is_absolute(), 'invalid_secret_file')
    require(vault['ca_file'] is None or (isinstance(vault['ca_file'], str)
            and Path(vault['ca_file']).is_absolute()), 'invalid_vault_ca')
    require(profile.get('aws_profile') is None or (isinstance(profile['aws_profile'], str)
            and re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', profile['aws_profile'])), 'invalid_aws_profile')
    return profile


def profile_digest(profile):
    validate_profile(profile)
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def endpoint_name(profile):
    # Full digest is the endpoint name: changing any profile field invalidates
    # CertLord's existing destination target hash without a new daemon schema.
    return profile_digest(profile)


def bind(profile, digest, selectors):
    expected = profile_digest(profile)
    require(digest == expected, 'profile_changed')
    require(len(selectors) == 4, 'invalid_selectors')
    identity, domain, generation, destination = selectors
    require((identity, domain, destination) == (profile['certificate_id'],
            profile['target']['domain'], profile['destination']), 'wrong_job_target')
    require(re.fullmatch(r'[a-f0-9]{64}', generation), 'invalid_generation')
    return generation
