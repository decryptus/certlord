"""Sanitized failure evidence for the disposable lifecycle harness."""
import re
from pathlib import Path


CATEGORIES = (
    'Another instance of Certbot is already running',
    'Connection refused', 'Max retries exceeded', 'Read timed out',
    'Certbot failed to authenticate', 'Some challenges have failed',
    'challenge is invalid', 'Error determining zone',
    'HTTPError', 'HTTP 503', 'HTTP 401', 'HTTP 403',
    'Failed to establish a new connection', 'max retries exceeded',
    'Failed to renew', 'Failed to parse', 'does not appear to be running',
    'Performing the following challenges:',
    'urn:ietf:params:acme:error:unauthorized',
    'urn:ietf:params:acme:error:connection',
    'urn:ietf:params:acme:error:dns',
)


def collect(directory):
    """Return locations and fixed categories, never log lines or error messages.

    Certbot keeps its own log below --logs-dir, separate from worker stdout.
    Include rotations because a scheduler can start another attempt before failure.
    """
    result = {}
    logs = sorted(directory.glob('*.log'))
    logs += sorted((directory / 'certbot/logs').glob('letsencrypt.log*'))
    for log in logs:
        locations = []
        try:
            log_text = log.read_text(errors='replace')
        except OSError:
            # Daemons are still alive here: rotation must not mask the test error.
            result[str(log.relative_to(directory))] = {
                'locations': [], 'categories': ['Log unavailable']}
            continue
        for line in log_text.splitlines():
            match = re.match(r'\s*File "([^"]+)", line ([0-9]+), in ([a-zA-Z_][a-zA-Z_0-9]*)', line)
            if match:
                locations.append({'file': Path(match[1]).name,
                                  'line': int(match[2]), 'function': match[3]})
            elif re.match(r'^[A-Za-z_][A-Za-z_0-9.]*(Error|Exception):', line):
                locations.append({'exception': line.split(':', 1)[0]})
        matched = [category for category in CATEGORIES if category in log_text]
        if locations or matched:
            result[str(log.relative_to(directory))] = {
                'locations': locations[-15:], 'categories': matched}
    return result
