"""Explicit configured destinations, bounded TLS probes and allowlisted results."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from certlord.adapters.processes import CommandRunner, CommandTimeout, CommandInterrupted
from certlord.services.certificate_ids import require_certificate_id

from certlord.services.verification import ERROR_CODES


class TlsVerifier:
    def __init__(self, config, stop_event, grace=2):
        if config is None:
            config = {}
        if not isinstance(config, dict) or set(config) - {'timeout', 'targets'}:
            raise ValueError('Invalid tls_verification configuration')
        timeout = config.get('timeout', 10)
        if (type(timeout) not in (float, int) or not math.isfinite(timeout)
                or timeout <= 0 or timeout > 300):
            raise ValueError('TLS verification timeout must be between 0 and 300 seconds')
        self.runner = CommandRunner(stop_event, timeout, grace)
        targets = config.get('targets', {})
        if not isinstance(targets, dict):
            raise ValueError('TLS verification targets must map certificate UUIDs to destinations')
        self.targets = {}
        for identity, target in targets.items():
            require_certificate_id(identity)
            if not isinstance(target, dict) or set(target) - {'host', 'port', 'ca_file'}:
                raise ValueError('Invalid TLS verification destination')
            host, port, ca = target.get('host'), target.get('port', 443), target.get('ca_file')
            if not isinstance(host, str) or not host or len(host) > 253:
                raise ValueError('TLS verification host required')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                           for label in host.split('.')):
                    raise ValueError('TLS verification host must be an IP address or DNS name') from None
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('TLS verification port must be an integer between 1 and 65535')
            if ca is not None and (not isinstance(ca, str) or not Path(ca).is_absolute() or not Path(ca).is_file()):
                raise ValueError('TLS verification ca_file must be an existing absolute file path')
            self.targets[identity] = {'host': host, 'port': port, 'ca_file': ca}

    def configured(self, identity):
        return identity in self.targets

    def verify(self, identity, domain, record):
        target = self.targets[identity]
        result = {'status': 'failed', 'error_code': 'invalid_stored_certificate'}
        expected = None
        try:
            expected = x509.load_pem_x509_certificate(record['cert'].encode('ascii')).fingerprint(hashes.SHA256()).hex()
        except (KeyError, ValueError, TypeError, AttributeError, UnicodeError):
            pass
        else:
            args = [sys.executable, '-m', 'certlord.adapters.tls_probe', target['host'],
                    str(target['port']), domain, target['ca_file'] or '', expected, str(self.runner.timeout)]
            try:
                code, stdout, _stderr = self.runner.run(args, os.environ.copy())
                parsed = json.loads(stdout) if code == 0 else {}
                actual = parsed.get('observed_fingerprint_sha256')
                if actual is not None and (not isinstance(actual, str) or not re.fullmatch('[0-9a-f]{64}', actual)):
                    raise ValueError('Invalid probe fingerprint')
                if parsed.get('status') == 'verified' and actual == expected and parsed.get('error_code') is None:
                    result = {'status': 'verified', 'error_code': None, 'observed_fingerprint_sha256': actual}
                elif parsed.get('status') == 'failed' and parsed.get('error_code') in ERROR_CODES:
                    result = {'status': 'failed', 'error_code': parsed['error_code']}
                    if actual is not None:
                        result['observed_fingerprint_sha256'] = actual
                else:
                    raise ValueError('Invalid probe result')
            except CommandInterrupted:
                raise
            except CommandTimeout:
                result = {'status': 'failed', 'error_code': 'timeout'}
            except Exception:
                result = {'status': 'failed', 'error_code': 'probe_failed'}
        result.update(checked_at=datetime.now(timezone.utc).isoformat(),
                      expected_fingerprint_sha256=expected,
                      target_sha256=hashlib.sha256(json.dumps(dict(target, server_name=domain),
                                                            sort_keys=True).encode()).hexdigest())
        return result
