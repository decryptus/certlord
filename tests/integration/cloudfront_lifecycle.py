"""Real Vault/AppRole, Redis, Auton and TLS; controlled HTTP provider, NEVER AWS."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes
import requests
import yaml

from certlord.cloudfront.config import bind, profile_digest
from certlord.cloudfront.job import execute
from certlord.cloudfront.ledger import Ledger
from certlord.cloudfront.material import material_digest
from certlord.cloudfront.writer import Renewal
from certlord.adapters.tls_verification import TlsVerifier

SCRIPT = Path(__file__).resolve()
ARN = 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555'


class ControlledProvider:
    def __init__(self, url): self.url = url
    def read(self):
        response = requests.get(self.url, timeout=5); response.raise_for_status()
        data = response.json()
        leaf = x509.load_pem_x509_certificate(data['cert'].encode())
        return {'leaf': leaf, 'host': 'synthetic.cloudfront.net',
                'fingerprint': leaf.fingerprint(hashes.SHA256()).hex(),
                'material_sha256': material_digest(leaf, data['chain'])}
    def reimport(self, candidate):
        response = requests.post(self.url, json=candidate, timeout=5); response.raise_for_status()


def job(args):
    fixture = json.loads(args.fixture.read_text())
    profile = fixture['profile']
    digest = fixture['digest']
    generation = bind(profile, digest, args.selectors)
    stop = threading.Event()
    verifier = TlsVerifier({'timeout': 2, 'targets': {profile['certificate_id']: fixture['tls']}}, stop)
    try:
        result = execute(profile, digest, generation, stop, provider=ControlledProvider(fixture['provider']),
            verify=lambda record, _: verifier.verify(profile['certificate_id'], profile['target']['domain'], record))
    except Exception:
        print('{"status":"failed","error_code":"controlled_job_failed"}')
        return 1
    print(json.dumps(result))
    return 0


def exercise(source, directory, stack, env, config, config_path, daemon, vault,
             api, identity, domain, replacement_material, ca_file, phase):
    from lifecycle import free_port, write_yaml, start, stop, wait_for, run, http_thread, require, served_fingerprint
    root = directory / 'cloudfront'
    root.mkdir(mode=0o700)
    state = root / 'state'; state.mkdir(mode=0o700)
    credentials = yaml.safe_load(Path(config['credentials']).read_text())
    vault_url = credentials['vault']['uri']
    vault_path = 'certlord-fixture/' + identity + '/' + domain
    def stored():
        return vault.secrets.kv.v2.read_secret_version(vault_path, raise_on_deleted_version=True)['data']['data']
    # Terminate TLS in a private loopback proxy to exercise the production HTTPS
    # AppRole reader against the existing disposable real Vault instance.
    class Quiet(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
    class VaultProxy(Quiet):
        def forward(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            response = requests.request(self.command, vault_url + self.path, data=body,
                headers={k: v for k, v in self.headers.items() if k.lower() in ('x-vault-token', 'content-type')}, timeout=5)
            self.send_response(response.status_code); self.end_headers(); self.wfile.write(response.content)
        do_GET = do_POST = forward
    proxy = ThreadingHTTPServer(('127.0.0.1', 0), VaultProxy)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca_file, directory / 'transport.key')
    proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
    http_thread(stack, proxy)
    vault.sys.create_or_update_policy('cloudfront-fixture', 'path "secret/data/' + vault_path + '" { capabilities = ["read"] }')
    if 'approle/' not in vault.sys.list_auth_methods()['data']:
        vault.sys.enable_auth_method('approle')
    vault.auth.approle.create_or_update_approle('cloudfront-fixture', token_policies=['default', 'cloudfront-fixture'])
    role = vault.auth.approle.read_role_id('cloudfront-fixture')['data']['role_id']
    secret = vault.auth.approle.generate_secret_id('cloudfront-fixture')['data']['secret_id']
    for name, value in (('role', role), ('secret', secret)):
        path = root / name; path.write_text(value); path.chmod(0o600)
    profile = {'target': {'account_id': '123456789012', 'certificate_arn': ARN,
        'distribution_id': 'E123EXAMPLE', 'domain': domain}, 'certificate_id': identity,
        'destination': 'cloudfront', 'state_dir': str(state), 'poll_interval': 1, 'propagation_timeout': 40,
        'vault': {'url': 'https://localhost:' + str(proxy.server_port), 'mount': 'secret',
        'key_name': 'certlord-fixture', 'role_id_file': str(root / 'role'),
        'secret_id_file': str(root / 'secret'), 'ca_file': str(ca_file)}}
    digest = profile_digest(profile)
    remote = {'record': stored(), 'calls': 0, 'hold': True, 'lost': False}
    def install(record):
        bundle = root / ('bundle-' + hashlib.sha256(record['cert'].encode()).hexdigest())
        bundle.mkdir(mode=0o700, exist_ok=True)
        (bundle / 'cert.pem').write_text(record['cert'] + record['chain'])
        (bundle / 'key.pem').write_text(record['key']); (bundle / 'key.pem').chmod(0o600)
        link = root / 'next'; link.symlink_to(bundle); link.replace(root / 'current')
    install(remote['record'])
    class ProviderHandler(Quiet):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(json.dumps({k: remote['record'][k] for k in ('cert', 'chain')}).encode())
        def do_POST(self):
            remote['record'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            remote['calls'] += 1
            if not remote['hold']: install(remote['record'])
            # Effect has committed, caller receives an error instead of a receipt.
            self.send_response(503 if remote['lost'] else 200); self.end_headers()
    provider_server = ThreadingHTTPServer(('127.0.0.1', 0), ProviderHandler)
    http_thread(stack, provider_server)
    provider_url = 'http://127.0.0.1:' + str(provider_server.server_port)
    class TLSListener(ThreadingHTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / 'current/cert.pem', root / 'current/key.pem')
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close(); raise
    tls = TLSListener(('127.0.0.1', 0), Quiet)
    http_thread(stack, tls)
    tls_spec = {'host': '127.0.0.1', 'port': tls.server_port, 'ca_file': str(ca_file)}
    fixture = root / 'fixture.json'
    fixture.write_text(json.dumps({'profile': profile, 'digest': digest, 'provider': provider_url, 'tls': tls_spec}))
    fixture.chmod(0o600)
    password = 'disposable-cloudfront-password'
    passwd = root / 'passwd'
    passwd.write_text('fixture:{SHA}' + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode() + '\n')
    passwd.chmod(0o600)
    port = free_port(); origin = 'http://127.0.0.1:' + str(port)
    routes = yaml.safe_load((source / 'tests/integration/auton-routes.yml').read_text())
    for module in routes.values():
        for route in module.get('routes', {}).values(): route['auth'] = True
    auton_conf = {'general': {'listen_addr': '127.0.0.1', 'listen_port': port, 'max_workers': 2,
        'lock_timeout': 5, 'auth_basic': 'Disposable CloudFront', 'auth_basic_file': str(passwd)},
        'modules': routes, 'endpoints': {digest: {'plugin': 'subproc', 'users': {'fixture': True},
        'config': {'prog': sys.executable, 'args': [str(SCRIPT), '--fixture', str(fixture)],
                   'timeout': 60, 'disallow-env': True}}}}
    auton_path = write_yaml(root / 'auton.yml', auton_conf)
    auton = start(stack, ['autond', '-f', '-c', auton_path, '-p', str(root / 'auton.pid'),
        '--logfile', str(root / 'auton.log')], env, root, 'auton')
    wait_for(lambda: requests.get(origin + '/health', auth=('fixture', password), timeout=1).ok,
             'CloudFront fixture Auton', [auton])
    credentials['cloudfront'] = {'uri': origin, 'endpoint': digest, 'auth-user': 'fixture', 'auth-passwd': password}
    write_yaml(Path(config['credentials']), credentials)
    module = config['modules']['ssl_certs']
    module['routes']['index'].update(at_start=False, at_stop=False)
    module['deployment_destinations'] = {identity: {'cloudfront': {'credentials': 'cloudfront', 'tls': tls_spec}}}
    module['command_timeout'] = 4
    write_yaml(Path(config_path), config)
    def restart(process):
        stop(process)
        value = start(stack, ['certlord', '-f', '-c', config_path, '-p', str(root / 'certlord.pid'),
            '--logfile', str(root / 'certlord.log')], env, root, 'certlord')
        wait_for(lambda: requests.get(api + '/api/certificates', timeout=1).ok, 'CloudFront fixture CertLord', [value])
        return value
    daemon = restart(daemon)
    def cycle(name, label):
        run([sys.executable, str(source / 'tests/integration/lifecycle.py'), 'cycle',
             '--config', config_path, '--cycle', name], env, root, label)
    def detail(): return requests.get(api + '/api/certificates/' + identity, timeout=5).json()
    def replace(offset):
        response = requests.put(api + '/api/certificates/' + identity + '/material',
            json=dict(replacement_material(offset), expected_version=detail()['version']), timeout=10)
        require(response.ok, 'CloudFront fixture replacement failed')
    def entry():
        ledger = Ledger(state)
        try: return ledger.read(ARN)
        finally: ledger.close()
    replace(50)
    cycle('crawl', 'cloudfront-queue'); cycle('deploy', 'cloudfront-accepted-not-served')
    require(remote['calls'] == 1 and entry()['state'] == 'accepted', 'Import not durably accepted')
    require(detail()['status'] == 'generated' and detail()['deployment']['verified'] == 0,
            'Provider acceptance was mistaken for TLS verification')
    from certlord.adapters.redis_client import redis_adapter
    pending = redis_adapter(config, 'ssl_certs').servers['ssl_certs']['conn']
    require(pending.scard(config['general']['server_id']) > 0, 'Pending remote job lost its Redis queue')
    attempt = detail()['deployment']['destinations'][0]['attempt_id']
    daemon = restart(daemon)
    remote['hold'] = False; install(remote['record'])
    wait_for(lambda: entry()['state'] == 'verified', 'CloudFront fixture TLS propagation', [auton])
    cycle('deploy', 'cloudfront-resume-receipt')
    require(detail()['status'] == 'deployed' and remote['calls'] == 1
            and detail()['deployment']['destinations'][0]['attempt_id'] == attempt,
            'Restart repeated the import or lost the receipt')
    require(served_fingerprint(tls.server_port, ca_file, domain) == entry()['fingerprint'], 'Wrong live TLS leaf')
    phase('cloudfront-controlled-import-real-approle-auton-redis-delayed-tls-and-restart')
    replace(60); remote['lost'] = True
    cycle('crawl', 'cloudfront-queue-lost-reply'); cycle('deploy', 'cloudfront-lost-reply')
    require(entry()['state'] == 'quarantined' and remote['calls'] == 2, 'Lost reply did not quarantine ARN')
    def retry():
        response = requests.post(api + '/api/certificates/' + identity + '/destinations/cloudfront/retry',
            json={'expected_version': detail()['version'], 'acknowledge_uncertain': True}, timeout=5)
        require(response.ok, 'CloudFront fixture retry failed')
        cycle('crawl', 'cloudfront-queue-retry'); cycle('deploy', 'cloudfront-retry')
    retry()
    require(remote['calls'] == 2 and detail()['deployment']['verified'] == 0, 'Quarantine was bypassed')
    # Only this controlled server guarantees its synchronous handler has finished.
    # This explicit assertion must NEVER be inferred from a real AWS read-back.
    ledger = Ledger(state)
    try:
        provider = ControlledProvider(provider_url)
        Renewal(profile, digest, ledger, None, provider, None, threading.Event()).reconcile(
            entry()['intent_id'], provider.read()['fingerprint'], True)
    finally: ledger.close()
    remote['lost'] = False; retry()
    require(remote['calls'] == 2 and detail()['status'] == 'deployed', 'Reconciliation replayed an installed leaf')
    phase('cloudfront-controlled-lost-reply-quarantine-explicit-reconciliation-without-reimport')
    return daemon


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('selectors', nargs=4)
    raise SystemExit(job(parser.parse_args()))
