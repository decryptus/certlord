"""One TLS handshake in an owned subprocess; only sanitized JSON leaves it."""
import hashlib
import json
import socket
import ssl
import sys


def probe(host, port, server_name, ca_file, expected, timeout):
    try:
        context = ssl.create_default_context(cafile=ca_file or None)
        context.hostname_checks_common_name = False
        with socket.create_connection((host, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=server_name) as secured:
                actual = hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
        if actual != expected:
            return {'status': 'failed', 'error_code': 'fingerprint_mismatch',
                    'observed_fingerprint_sha256': actual}
        return {'status': 'verified', 'error_code': None,
                'observed_fingerprint_sha256': actual}
    except ssl.SSLCertVerificationError:
        return {'status': 'failed', 'error_code': 'tls_validation_failed'}
    except (TimeoutError, socket.timeout):
        return {'status': 'failed', 'error_code': 'timeout'}
    except ssl.SSLError:
        return {'status': 'failed', 'error_code': 'tls_handshake_failed'}
    except OSError:
        return {'status': 'failed', 'error_code': 'connection_or_trust_store_failed'}


def main(argv):
    try:
        host, port, server_name, ca_file, expected, timeout = argv
        result = probe(host, int(port), server_name, ca_file, expected, float(timeout))
    except Exception:
        result = {'status': 'failed', 'error_code': 'probe_failed'}
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
