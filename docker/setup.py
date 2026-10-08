"""Explicit, local single-host bootstrap; recovery keys never reach app containers."""
import argparse
import base64
import crypt
import json
import os
from pathlib import Path
import secrets
import sys
import time

import hvac
import yaml

ROOT = Path('/bootstrap')
TEMPLATES = Path('/opt/certlord-docker')


def write(path, value, service=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(value)
    temporary.chmod(0o600)
    if service:
        os.chown(temporary, 10001, 10001)
    temporary.replace(path)


def dump(path, value, service=True):
    write(path, yaml.safe_dump(value, sort_keys=False), service)


def initialize(args, client):
    marker = ROOT / 'initialized'
    if marker.exists():
        print('Already initialized; configuration and credentials were preserved.')
        return
    recovery = ROOT / 'vault-recovery.json'
    if not client.sys.is_initialized():
        if recovery.exists():
            raise RuntimeError('Recovery file exists but Vault is empty; restore before continuing')
        result = client.sys.initialize(secret_shares=1, secret_threshold=1)
        write(recovery, json.dumps(result))
    if not recovery.exists():
        raise RuntimeError('Existing Vault without matching recovery file; refusing to take ownership')
    keys = json.loads(recovery.read_text())
    client.sys.submit_unseal_key(keys['keys_base64'][0])
    client.token = keys['root_token']
    if not client.is_authenticated():
        raise RuntimeError('Bootstrap root token unavailable; operator recovery required')
    engines = client.sys.list_mounted_secrets_engines()['data']
    if 'secret/' not in engines:
        client.sys.enable_secrets_engine('kv', path='secret', options={'version': '2'})
    methods = client.sys.list_auth_methods()['data']
    if 'approle/' not in methods:
        client.sys.enable_auth_method('approle')
    policy = (TEMPLATES / 'vault-policy.hcl').read_text()
    client.sys.create_or_update_policy('certlord', policy)
    client.auth.approle.create_or_update_approle('certlord', token_policies=['certlord'],
        token_no_default_policy=True, token_ttl='1h', token_max_ttl='4h',
        secret_id_ttl=0, secret_id_num_uses=0)
    role = client.auth.approle.read_role_id('certlord')['data']['role_id']
    secret = client.auth.approle.generate_secret_id('certlord')['data']['secret_id']
    passwords = {name: secrets.token_urlsafe(32) for name in ('operator', 'connector', 'reader', 'auton')}
    for directory in ('certlord', 'auton', 'deploy'):
        path = ROOT / directory
        path.mkdir(exist_ok=True)
        path.chmod(0o700)
        os.chown(path, 10001, 10001)
    def htpasswd(names):
        return ''.join(name + ':' + crypt.crypt(passwords[name],
            crypt.mksalt(crypt.METHOD_SHA512, rounds=100000)) + '\n' for name in names)
    write(ROOT / 'certlord/api.htpasswd', htpasswd(('operator', 'connector', 'reader')), True)
    write(ROOT / 'auton/api.htpasswd', htpasswd(('auton',)), True)
    dump(ROOT / 'certlord/health.yml', {'user': 'reader', 'password': passwords['reader']})
    write(ROOT / 'admin-login.txt', 'User: operator\nPassword: ' + passwords['operator'] + '\n')
    config = yaml.safe_load((TEMPLATES / 'certlord.example.yml').read_text())
    general = config['general']
    general.update(server_id='certlord-compose', auth_basic='CertLord',
                   auth_basic_file='/etc/certlord/api.htpasswd')
    general['redis'] = {name: {'url': 'redis://redis:6379/%d?socket_timeout=5&socket_connect_timeout=5' % db}
                        for name, db in (('letsencrypt', 0), ('ssl_certs', 1))}
    config['credentials'] = '/etc/certlord/credentials.yml'
    config['api_authentication'] = {'backend': 'httpdis', 'permissions': {
        'operator': ['read', 'write', 'deploy'], 'connector': ['write', 'challenge'], 'reader': ['read']}}
    module = config['modules']['ssl_certs']
    module['certbot'] = {'become': {'enabled': False}, 'args': [
        '--non-interactive', '--agree-tos', '--email', args.email,
        '--server', 'https://acme-staging-v02.api.letsencrypt.org/directory',
        '--config-dir', '/var/lib/certlord/certbot/config',
        '--work-dir', '/var/lib/certlord/certbot/work',
        '--logs-dir', '/var/lib/certlord/certbot/logs',
        '--key-type', 'rsa', '--rsa-key-size', '2048',
        '-a', 'certbot-httpreq:auth', '-i', 'certbot-httpreq:installer',
        '--certbot-httpreq:auth-config', '/etc/certlord/connector.yml',
        '--certbot-httpreq:installer-config', '/etc/certlord/connector.yml', 'run']}
    module['auton'] = {'receipt_mode': True, 'become': {'enabled': False}}
    dump(ROOT / 'certlord/certlord.yml', config)
    dump(ROOT / 'certlord/credentials.yml', {
        'vault': {'uri': 'http://vault:8200', 'token': '-', 'role_id': role,
                  'secret_id': secret, 'mount': 'secret', 'key_name': 'certlord-certificates'},
        'auton': {'uri': 'http://auton:8080', 'endpoint': 'deploy',
                  'auth-user': 'auton', 'auth-passwd': passwords['auton']}})
    authorization = 'Basic ' + base64.b64encode(('connector:' + passwords['connector']).encode()).decode()
    connector = {phase: {'uri': 'http://127.0.0.1:8666', 'headers': {'Authorization': authorization}}
                 for phase in ('perform', 'cleanup', 'deploy')}
    connector['deploy']['path'] = '/api/ssl-certs/save'
    dump(ROOT / 'certlord/connector.yml', connector)
    routes = yaml.safe_load((TEMPLATES / 'auton-routes.yml').read_text())
    for route in routes['job']['routes'].values():
        route['auth'] = True
    dump(ROOT / 'auton/auton.yml', {
        'general': {'listen_addr': '0.0.0.0', 'listen_port': 8080, 'auth_mode': 'required',
                    'auth_basic': 'Auton', 'auth_basic_file': '/etc/auton/api.htpasswd', 'max_workers': 3},
        'modules': routes,
        'endpoints': {'deploy': {'plugin': 'subproc', 'config': {
            'prog': '/bin/sh', 'args': ['/deploy/deploy.sh'], 'timeout': 240,
            'disallow-args': True, 'disallow-env': True}}}})
    # No dummy successful job: pending deployment must remain pending until configured.
    if not (ROOT / 'deploy/deploy.sh').exists():
        write(ROOT / 'deploy/deploy.sh', '#!/bin/sh\necho "Configure /deploy/deploy.sh for your destination before deployment." >&2\nexit 78\n', True)
    write(marker, '1\n')
    client.auth.token.revoke_self()
    keys.pop('root_token', None)
    write(recovery, json.dumps(keys))
    print('Initialized. Read .local/admin-login.txt locally. Protect and back up .local/vault-recovery.json offline.')
    print('Vault is unsealed. Configure the deployment job before requesting certificates.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('init', 'unseal'))
    parser.add_argument('--email')
    args = parser.parse_args()
    if args.command == 'init' and (not args.email or '@' not in args.email or '\n' in args.email):
        parser.error('init requires --email with your ACME contact address')
    os.umask(0o077)
    ROOT.mkdir(exist_ok=True)
    ROOT.chmod(0o700)
    client = hvac.Client(url='http://vault:8200', timeout=5)
    for attempt in range(30):
        try:
            client.sys.is_initialized()
            break
        except Exception:
            if attempt == 29:
                raise RuntimeError('Vault did not become reachable') from None
            time.sleep(1)
    if args.command == 'init':
        initialize(args, client)
    else:
        keys = json.loads((ROOT / 'vault-recovery.json').read_text())
        client.sys.submit_unseal_key(keys['keys_base64'][0])
        if client.sys.is_sealed():
            raise RuntimeError('Vault remains sealed')
        print('Vault is unsealed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Backend exceptions can contain sensitive request/response data.
        print('Setup failed (' + type(error).__name__ + '); check Vault availability and the protected bootstrap files. No files were deleted.', file=sys.stderr)
        sys.exit(1)
