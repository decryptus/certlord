"""API authorization uses identities, never storage credentials."""
API_OPERATIONS = frozenset(('read', 'write', 'deploy', 'challenge', 'issue'))


class AccessDenied(Exception):
    pass


class ApiAccess(object):
    def __init__(self, permissions):
        self._permissions = dict((name, frozenset(ops)) for name, ops in permissions.items())
        if any(not ops <= API_OPERATIONS for ops in self._permissions.values()):
            raise ValueError('Unknown API permission')

    def require(self, principal, operation):
        granted = self._permissions.get(principal, ())
        # Existing writers retain the ACME callback after upgrades.
        if operation == 'issue' and 'write' in granted:
            return principal
        if operation not in granted:
            raise AccessDenied('API operation not permitted')
        return principal
