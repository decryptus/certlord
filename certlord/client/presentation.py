"""Shared read-only destination details for the CLI and terminal browser."""


def endpoint_lines(record):
    return ['Status: ' + record['status'],
            'Connection: %s:%s' % (record['connect_host'], record['port']),
            'TLS name: ' + record['server_name'],
            'Fresh: ' + str(record['fresh']),
            'Last check (Unix seconds): ' + str(record['checked_at']),
            'Last result: ' + str(record['last_status']),
            'Expected SHA-256: ' + (record['expected_fingerprint_sha256'] or 'not pinned'),
            'Served SHA-256: ' + (record['observed_fingerprint_sha256'] or 'unavailable'),
            'Error: ' + (record['error_code'] or 'none')]


def destination_lines(record):
    deployment = record.get('deployment')
    if not isinstance(deployment, dict):
        return []
    result = ['Destinations: %s (%s/%s verified)' %
              (deployment['status'], deployment['verified'], deployment['total']),
              'Expected SHA-256: ' + (deployment.get('expected_fingerprint_sha256') or 'unavailable')]
    for target in deployment['destinations']:
        result.append('%s: %s%s' % (target['name'], target['status'],
                      ' (' + target['error_code'] + ')' if target.get('error_code') else ''))
        verification = target.get('verification') or {}
        if verification.get('observed_fingerprint_sha256'):
            result.append('  Served SHA-256: ' + verification['observed_fingerprint_sha256'])
        if verification.get('error_code'):
            result.append('  TLS: ' + verification['error_code'])
    return result
