"""Experimental Auton renewal job; provider acceptance is not live qualification."""
import argparse
from contextlib import ExitStack
import json
import logging
import os
from pathlib import Path
import signal
import stat
import threading

import hvac

from certlord.adapters.vault_auth import VaultAppRoleAuth, VaultSession
from certlord.adapters.vault_store import VaultCertificateStore
from certlord.adapters.tls_verification import TlsVerifier
from certlord.cloudfront.aws import AwsProvider
from certlord.cloudfront.config import JobError, require, validate_profile, profile_digest, endpoint_name, bind
from certlord.cloudfront.ledger import Ledger
from certlord.cloudfront.writer import Renewal


def read_private(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and not stat.S_IMODE(info.st_mode) & 0o077, 'insecure_private_file')
        value = stream.read(limit + 1)
        require(len(value) <= limit, 'private_file_too_large')
        return value


def vault_reader(profile):
    spec = profile['vault']
    auth = VaultAppRoleAuth(read_private(spec['role_id_file']).strip(),
                            read_private(spec['secret_id_file']).strip())
    session = VaultSession(spec['url'], auth,
        client_factory=lambda **kwargs: hvac.Client(verify=spec['ca_file'] or True, **kwargs))
    store = VaultCertificateStore(session, spec['key_name'], spec['mount'])
    return lambda: store.get_versioned(profile['certificate_id'], profile['target']['domain'])[0]


def execute(profile, digest, generation, stop, *, provider=None, read=None, verify=None):
    """Injected boundaries are for local acceptance; the CLI has no provider override."""
    with ExitStack() as stack:
        ledger = Ledger(profile['state_dir'])
        stack.callback(ledger.close)
        if provider is None:
            import boto3
            provider = AwsProvider(profile['target'], boto3.Session(profile_name=profile.get('aws_profile')))
            stack.callback(provider.close)
        read = read or vault_reader(profile)
        if verify is None:
            def verify(record, snapshot):
                verifier = TlsVerifier({'timeout': 10, 'targets': {
                    profile['certificate_id']: {'host': snapshot['host'], 'port': 443}}}, stop)
                return verifier.verify(profile['certificate_id'], profile['target']['domain'], record)
        return Renewal(profile, digest, ledger, read, provider, verify, stop).run(generation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('profile', 'run', 'status', 'reconcile'))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--profile-sha256')
    parser.add_argument('--expected-intent')
    parser.add_argument('--observed-fingerprint')
    parser.add_argument('--acknowledge-quiesced', action='store_true')
    parser.add_argument('selectors', nargs='*', help='UUID domain generation destination (Auton arguments)')
    args = parser.parse_intermixed_args(argv)
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _sig, _frame: stop.set())
    try:
        profile = validate_profile(json.loads(read_private(args.config)))
        digest = profile_digest(profile)
        if args.mode == 'profile':
            require(not args.selectors, 'unexpected_selectors')
            result = {'status': 'profile', 'profile_sha256': digest, 'auton_endpoint': endpoint_name(profile)}
        elif args.mode == 'run':
            generation = bind(profile, args.profile_sha256, args.selectors)
            result = execute(profile, digest, generation, stop)
        else:
            require(args.profile_sha256 == digest and not args.selectors, 'profile_changed')
            with ExitStack() as stack:
                ledger = Ledger(profile['state_dir'])
                stack.callback(ledger.close)
                if args.mode == 'status':
                    result = {'status': 'ledger', 'entry': ledger.read(profile['target']['certificate_arn'])}
                else:
                    require(args.acknowledge_quiesced and args.expected_intent and args.observed_fingerprint,
                            'reconciliation_acknowledgement_required')
                    import boto3
                    provider = AwsProvider(profile['target'], boto3.Session(profile_name=profile.get('aws_profile')))
                    stack.callback(provider.close)
                    result = Renewal(profile, digest, ledger, None, provider, None, stop).reconcile(
                        args.expected_intent, args.observed_fingerprint, args.acknowledge_quiesced)
    except JobError as error:
        result = {'status': 'failed', 'error_code': str(error)}
    except Exception:
        result = {'status': 'failed', 'error_code': 'job_dependency_or_configuration_failed'}
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('status') == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
