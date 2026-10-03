"""Explicit provider selection; unsupported backends fail at startup."""
import os

from certlord.adapters.api_auth import HttpdisApiAuth, LocalFixtureAuth, ApiRequestAccess
from certlord.adapters.vault_auth import VaultTokenAuth, VaultAppRoleAuth, VaultSession
from certlord.adapters.vault_store import VaultCertificateStore
from certlord.classes.exceptions import CertLordConfigError
from certlord.services.api_access import ApiAccess, API_OPERATIONS


def vault_settings(config):
    credentials = config.get('credentials') or {}
    creds = credentials.get('vault')
    if not isinstance(creds, dict):
        raise CertLordConfigError('Missing Vault credentials configuration')

    def setting(name):
        return creds.get(name.lower()) or os.environ.get('VAULT_' + name)

    url = creds.get('uri') or os.environ.get('VAULT_ADDR') or setting('URI')
    token, key_name = setting('TOKEN'), setting('KEY_NAME')
    if not url or not key_name:
        raise CertLordConfigError('Missing Vault address or key_name')
    role, secret = setting('ROLE_ID'), setting('SECRET_ID')
    if (not token or token == '-') and not (role and secret):
        raise CertLordConfigError('Missing Vault AppRole credentials')
    return {'url': url, 'token': token if token != '-' else None, 'role_id': role,
            'secret_id': secret, 'key_name': key_name, 'mount': creds.get('mount', 'secret')}


def certificate_store(config):
    storage = config.get('certificate_storage') or {}
    if storage.get('backend', 'vault') != 'vault':
        raise CertLordConfigError('Unsupported certificate storage backend')
    conf = vault_settings(config)
    auth = (VaultTokenAuth(conf['token']) if conf['token'] else
            VaultAppRoleAuth(conf['role_id'], conf['secret_id']))
    return VaultCertificateStore(VaultSession(conf['url'], auth), conf['key_name'], conf['mount'])


def api_access(config):
    general = config['general']
    auth = config.get('api_authentication') or {}
    mode = auth.get('backend', 'httpdis')
    if mode == 'local':
        if general.get('listen_addr') not in ('127.0.0.1', '::1'):
            raise CertLordConfigError('Local API authentication requires a loopback listener')
        return ApiRequestAccess(LocalFixtureAuth(), ApiAccess({'local': API_OPERATIONS}))
    if mode != 'httpdis':
        raise CertLordConfigError('Unsupported API authentication backend')
    return ApiRequestAccess(HttpdisApiAuth(), ApiAccess(auth.get('permissions') or {}))


def certificate_runtime(config, modconf):
    from certlord.adapters.redis_client import redis_adapter
    from certlord.adapters.commands import CommandBuilder
    from certlord.adapters.dns_policy import DnsPolicy
    from certlord.adapters.pending import PendingCertificates
    from certlord.services.monitoring import CertificateMonitoring
    from certlord.services.runtime import CertificateRuntime
    from certlord.services.cycle_progress import CycleProgress
    from certlord.adapters.cycle_progress import CycleProgressStore
    redis = redis_adapter(config, prefix='ssl_certs')
    if len(redis.servers) != 1:
        raise CertLordConfigError('Certificate deployment requires one authoritative Redis server')
    commands = CommandBuilder(config, modconf)
    commands._get_auton_cred()
    store = certificate_store(config)
    redis.ping()
    store.list_certificate_ids()
    checkers = {}
    for name, conf in (config.get('ssl_checkers') or {}).items():
        if not isinstance(conf, dict) or not conf.get('enabled', False):
            continue
        from certlord.classes.ssl_checker import SSL_CHECKERS
        if name not in SSL_CHECKERS:
            raise CertLordConfigError('Unsupported monitoring provider: %s' % name)
        checker = type(SSL_CHECKERS[name])()
        checker.init(conf, (config.get('credentials') or {}).get(name))
        checkers[name] = checker
    return CertificateRuntime(config, modconf, store, PendingCertificates(redis),
                              DnsPolicy(modconf), commands, CertificateMonitoring(checkers),
                              CycleProgress(CycleProgressStore(redis, config['general']['server_id'])))
