"""Three real Auton jobs/TLS targets, Vault CAS and Redis queue recovery."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import hvac
import requests
import yaml

NAMES = ('west', 'east', 'north')
SCRIPT = Path(__file__).resolve()


def install(args):
    from certlord.services.deployment import certificate_generation
    from lifecycle import require, certificate_checks
    conf = json.loads(args.job_config.read_text())
    require(args.destination in NAMES, 'Unexpected fixture destination')
    require(args.identity == conf['identity'] and args.domain == conf['domain'], 'Unexpected fixture selectors')
    root = Path(conf['directory']) / args.destination
    with (root / 'starts').open('a') as output:
        output.write('start\n')
    if (root / 'fail').exists():
        return 23
    vault = hvac.Client(url=conf['vault'], token=conf['token'])
    record = vault.secrets.kv.v2.read_secret_version(conf['path'], raise_on_deleted_version=True)['data']['data']
    require(certificate_generation(record) == args.generation, 'Superseded fixture generation')
    certificate_checks(record, args.domain)
    bundle = root / ('bundle-' + args.generation)
    bundle.mkdir(mode=0o700, exist_ok=True)
    (bundle / 'cert.pem').write_text(record['cert'] + record['chain'])
    (bundle / 'key.pem').write_text(record['key'])
    (bundle / 'key.pem').chmod(0o600)
    pending = root / 'next'
    pending.symlink_to(bundle)
    pending.replace(root / 'current')
    return 0


def exercise(source, directory, stack, env, config, config_path, daemon, vault,
             api, identity, domain, new_material, ca_file, phase):
    from lifecycle import free_port, write_yaml, start, stop, wait_for, run, http_thread, require, served_fingerprint
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    root = directory / 'destinations'
    root.mkdir(mode=0o700)
    credentials = yaml.safe_load(Path(config['credentials']).read_text())
    job_path = root / 'job.json'
    job_path.write_text(json.dumps({'directory': str(root), 'identity': identity, 'domain': domain,
        'vault': credentials['vault']['uri'], 'token': credentials['vault']['token'],
        'path': 'certlord-fixture/' + identity + '/' + domain}))
    job_path.chmod(0o600)
    password = 'disposable-destination-password'
    passwd = root / 'passwd'
    # Existing legacy Basic support is exercised only inside this loopback fixture.
    passwd.write_text('fixture:{SHA}' + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode() + '\n')
    passwd.chmod(0o600)
    port = free_port()
    origin = 'http://127.0.0.1:' + str(port)
    routes = yaml.safe_load((source / 'tests/integration/auton-routes.yml').read_text())
    for module in routes.values():
        for route in module.get('routes', {}).values():
            route['auth'] = True
    auton_conf = {'general': {'listen_addr': '127.0.0.1', 'listen_port': port, 'max_workers': 3,
        'lock_timeout': 5, 'auth_basic': 'Disposable destinations', 'auth_basic_file': str(passwd)},
        'modules': routes, 'endpoints': {'deploy-destination': {'plugin': 'subproc', 'users': {'fixture': True},
        'config': {'prog': sys.executable, 'args': [str(SCRIPT), '--job-config', str(job_path)],
                   'timeout': 20, 'disallow-env': True}}}}
    auton_path = write_yaml(root / 'auton.yml', auton_conf)
    auton = start(stack, ['autond', '-f', '-c', auton_path, '-p', str(root / 'auton.pid'),
        '--logfile', str(root / 'auton.log')], env, root, 'auton')
    wait_for(lambda: requests.get(origin + '/health', auth=('fixture', password), timeout=1).ok,
             'Named destination Auton', [auton])
    targets = {}
    ports = {}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
    class TLSListener(ThreadingHTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.bundle / 'cert.pem', self.bundle / 'key.pem')
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise
    for name in NAMES:
        path = root / name
        path.mkdir(mode=0o700)
        server = TLSListener(('127.0.0.1', 0), Handler)
        server.bundle = path / 'current'
        http_thread(stack, server)
        ports[name] = server.server_port
        profile = 'destination-' + name
        credentials[profile] = {'uri': origin, 'endpoint': 'deploy-destination',
                                'auth-user': 'fixture', 'auth-passwd': password}
        targets[name] = {'credentials': profile, 'tls': {
            'host': '127.0.0.1', 'port': server.server_port, 'ca_file': str(ca_file)}}
    write_yaml(Path(config['credentials']), credentials)
    module = config['modules']['ssl_certs']
    module['tls_verification']['targets'].pop(identity, None)
    module['deployment_destinations'] = {identity: targets}
    write_yaml(Path(config_path), config)

    def restart(process):
        stop(process)
        value = start(stack, ['certlord', '-f', '-c', config_path, '-p', str(root / 'certlord.pid'),
            '--logfile', str(root / 'certlord.log')], env, root, 'certlord')
        wait_for(lambda: requests.get(api + '/api/certificates', timeout=1).ok, 'Destination CertLord', [value])
        return value

    daemon = restart(daemon)
    def cycle(name, label):
        run([sys.executable, str(source / 'tests/integration/lifecycle.py'), 'cycle',
             '--config', config_path, '--cycle', name], env, root, label)
    def detail():
        response = requests.get(api + '/api/certificates/' + identity, timeout=5)
        require(response.ok, 'Destination detail failed')
        return response.json()
    def counts():
        return [(root / name / 'starts').read_text().count('start\n') for name in NAMES]
    (root / 'east/fail').touch()
    cycle('crawl', 'queue-named-destinations')
    cycle('deploy', 'partial-named-destinations')
    first = detail()
    require(first['status'] == 'generated' and first['deployment']['verified'] == 2
            and first['deployment']['status'] == 'partial', 'Partial deployment incorrectly acknowledged')
    require(counts() == [1, 1, 1], 'Unexpected destination execution count')
    daemon = restart(daemon)
    require(detail()['deployment'] == first['deployment'], 'Restart lost per-destination progress')
    cycle('deploy', 'restart-named-destinations')
    require(counts() == [1, 1, 1], 'Restart replayed a confirmed or failed command')
    (root / 'east/fail').unlink()
    retry = subprocess.run(['certlord', 'retry-destination', identity, 'east', '--expected-version',
        str(detail()['version']), '--url', api, '--json'], env=env, capture_output=True, timeout=15)
    require(retry.returncode == 0 and b'PRIVATE KEY' not in retry.stdout, 'Installed targeted retry failed')
    cycle('crawl', 'queue-targeted-retry')
    cycle('deploy', 'targeted-recovery')
    recovered = detail()
    require(recovered['status'] == 'deployed' and recovered['deployment']['verified'] == 3,
            'Targeted recovery did not verify every destination')
    require(counts() == [1, 2, 1], 'Targeted retry repeated a successful destination')
    for target in recovered['deployment']['destinations']:
        remote = requests.get(origin + '/status/deploy-destination/' + target['attempt_id'],
                              auth=('fixture', password), timeout=5)
        require(remote.ok and remote.json()['status'] == 'complete' and remote.json()['return_code'] == 0,
                'Destination receipt does not identify a successful real job')
        require(served_fingerprint(ports[target['name']], ca_file, domain)
                == recovered['deployment']['expected_fingerprint_sha256'], 'Destination served a different leaf')
    phase('three-real-destinations-partial-failure-restart-and-targeted-cli-retry')
    response = requests.put(api + '/api/certificates/' + identity + '/material',
        json=dict(new_material, expected_version=recovered['version']), timeout=10)
    require(response.ok and response.json()['deployment']['verified'] == 0, 'Replacement retained stale destination success')
    cycle('crawl', 'queue-new-destination-version')
    cycle('deploy', 'deploy-new-destination-version')
    expected = x509.load_pem_x509_certificate(new_material['cert'].encode()).fingerprint(hashes.SHA256()).hex()
    require(counts() == [2, 3, 2] and detail()['deployment']['verified'] == 3, 'New version missed destinations')
    for name in NAMES:
        require(served_fingerprint(ports[name], ca_file, domain) == expected, 'New leaf missing at destination')
    require(requests.post(api + '/api/certificates/' + identity + '/destinations/east/retry',
        json={'expected_version': recovered['version']}, timeout=5).status_code == 409,
        'Stale retry accepted after replacement')
    phase('replacement-invalidates-all-destination-evidence-and-serves-new-leaf-everywhere')
    from tls_endpoints import exercise as endpoint_acceptance
    return endpoint_acceptance(config, config_path, daemon, restart, api, ports, domain, ca_file,
        expected, detail, counts, env, phase)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--job-config', type=Path, required=True)
    parser.add_argument('identity')
    parser.add_argument('domain')
    parser.add_argument('generation')
    parser.add_argument('destination')
    sys.exit(install(parser.parse_args()))
