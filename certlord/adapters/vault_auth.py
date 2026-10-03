"""Vault session credentials, separate from certificate persistence and API users."""
import threading

import hvac

from certlord.ports.certificates import StorageError, StorageSession


class VaultTokenAuth(object):
    def __init__(self, token):
        self._token = token

    def authenticate(self, client):
        client.token = self._token


class VaultAppRoleAuth(object):
    def __init__(self, role_id, secret_id):
        self._role_id, self._secret_id = role_id, secret_id

    def authenticate(self, client):
        client.auth.approle.login(self._role_id, self._secret_id)


class VaultSession(StorageSession):
    def __init__(self, url, authenticator, client_factory=hvac.Client):
        self._client = client_factory(url=url, timeout=10)
        self._authenticator = authenticator
        self._lock = threading.RLock()

    def client(self):
        with self._lock:
            try:
                if not self._client.is_authenticated():
                    self._authenticator.authenticate(self._client)
                    if not self._client.is_authenticated():
                        raise StorageError('Vault authentication rejected')
                return self._client
            except StorageError:
                raise
            except Exception:
                # Backend errors may contain credentials; do not expose them.
                raise StorageError('Vault authentication unavailable')
