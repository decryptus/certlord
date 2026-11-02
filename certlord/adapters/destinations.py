"""Explicit destination configuration and bounded Auton/TLS adapters."""
import copy
import hashlib
import ipaddress
import json
from urllib.parse import urlsplit

from certlord.adapters.commands import CommandBuilder
from certlord.adapters.auton_receipt import run_receipted, InvalidReceipt
from certlord.adapters.tls_verification import TlsVerifier
from certlord.services.certificate_ids import require_certificate_id
from certlord.services.deployment import DESTINATION_NAME, MAX_DESTINATIONS

DESTINATION_FIELDS = frozenset(('credentials', 'tls'))
CREDENTIAL_FIELDS = frozenset(('uri', 'endpoint', 'auth-user', 'auth-passwd'))


class DestinationPlan:
    def __init__(self, config, modconf, stop_event, runner):
        definitions = modconf.get('deployment_destinations', {})
        if not isinstance(definitions, dict) or len(definitions) > 10000:
            raise ValueError('Invalid deployment_destinations mapping')
        self.targets, self.commands, self.verifiers = {}, {}, {}
        self.runner = runner
        for identity, destinations in definitions.items():
            require_certificate_id(identity)
            if not isinstance(destinations, dict) or not 1 <= len(destinations) <= MAX_DESTINATIONS:
                raise ValueError('Each certificate requires 1 to 32 named destinations')
            if identity in (modconf.get('tls_verification') or {}).get('targets', {}):
                raise ValueError('Do not combine legacy and named TLS destinations for one certificate')
            self.targets[identity] = {}
            for name, spec in destinations.items():
                if not isinstance(name, str) or not DESTINATION_NAME.fullmatch(name):
                    raise ValueError('Invalid destination name')
                if not isinstance(spec, dict) or set(spec) != DESTINATION_FIELDS:
                    raise ValueError('Destination requires credentials and tls only')
                credential_name = spec['credentials']
                if not isinstance(credential_name, str):
                    raise ValueError('Destination credentials must name an explicit credential profile')
                credentials = (config.get('credentials') or {}).get(credential_name)
                if (not isinstance(credentials, dict) or set(credentials) - CREDENTIAL_FIELDS
                        or any(not isinstance(credentials.get(k), str) or not credentials[k]
                               for k in ('uri', 'endpoint', 'auth-user', 'auth-passwd'))):
                    raise ValueError('Destination requires explicit Auton origin, endpoint and credentials')
                uri = urlsplit(credentials['uri'])
                try:
                    local = uri.hostname == 'localhost' or ipaddress.ip_address(uri.hostname).is_loopback
                except ValueError:
                    local = False
                if uri.scheme != 'https' and not (uri.scheme == 'http' and local):
                    raise ValueError('Remote destination Auton origins require HTTPS')
                commands = CommandBuilder({'credentials': {'auton': credentials}},
                                          {'auton': dict(modconf.get('auton') or {}, receipt_mode=True)})
                command = commands.auton_cmd()
                verifier = TlsVerifier({'timeout': (modconf.get('tls_verification') or {}).get('timeout', 10),
                                        'targets': {identity: spec['tls']}}, stop_event, runner.grace)
                # Credential values are never persisted or exposed. Location and
                # endpoint changes invalidate success, as do TLS trust changes.
                descriptor = dict(command['receipt_target'], tls=verifier.targets[identity])
                if spec['tls'].get('ca_file'):
                    from pathlib import Path
                    descriptor['ca_sha256'] = hashlib.sha256(Path(spec['tls']['ca_file']).read_bytes()).hexdigest()
                self.targets[identity][name] = hashlib.sha256(
                    json.dumps(descriptor, sort_keys=True).encode()).hexdigest()
                self.commands[identity, name] = command
                self.verifiers[identity, name] = verifier

    def command(self, identity, domain, name, generation, attempt, submit):
        command = copy.deepcopy(self.commands[identity, name])
        # The operator-owned job must consume these selectors, check the current
        # generation before effects, and be idempotent for this version/target.
        for argument in (identity, domain, generation, name):
            command['args'] += ['-a', argument]
        code, receipt = run_receipted(self.runner, command, attempt, lambda receipt: None,
                                      initial_mode='run' if submit else 'status')
        if receipt.get('execution_uncertain'):
            raise InvalidReceipt('Remote execution outcome remains uncertain')
        return code == 0

    def verify(self, identity, domain, name, record):
        return self.verifiers[identity, name].verify(identity, domain, record)
