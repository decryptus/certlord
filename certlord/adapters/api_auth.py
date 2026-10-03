"""Delegate credential verification to HTTPdis; ignore caller-supplied identity headers."""


class HttpdisApiAuth(object):
    def authenticate(self, request):
        request.authenticate()
        return request.get_server_vars().get('HTTP_AUTH_USER')


class LocalFixtureAuth(object):
    """Only wired for explicit loopback development mode."""
    def authenticate(self, request):
        return 'local'


class ApiRequestAccess(object):
    def __init__(self, authenticator, policy):
        self.authenticator, self.policy = authenticator, policy

    def require(self, request, operation):
        return self.policy.require(self.authenticator.authenticate(request), operation)
