#!/usr/bin/env python3
# Copyright 2026 Adrien Delle Cave
# SPDX-License-Identifier: GPL-3.0-or-later
"""Private, disposable lifecycle acceptance; never use production configuration.

Real installed CertLord HTTP handlers, storage adapters, worker cycles, Certbot,
ACME HTTP Connector, Auton HTTP/CLI/job and a TLS listener. Cycles run explicitly
in separate bounded subprocesses; this is not a concurrent scheduler/soak test.
"""
import argparse
import uuid
import base64
import copy
import hashlib
import secrets
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import hvac
import psutil
import redis
import requests
import yaml

DOMAIN = 'one.example.test'
CERTIFICATE_ID = '1f204df3-610a-50cd-ba63-2cbb7012157d'
SECRET_PATH = 'certlord-fixture/' + CERTIFICATE_ID + '/' + DOMAIN
SERVER_ID = 'certlord-lifecycle-fixture'
PHASE_TIMEOUT = 120
PACKAGES = ('certlord', 'certbot', 'certbot-httpreq', 'acme-http-connector',
            'auton', 'autond', 'dwho', 'httpdis', 'sonicprobe', 'hvac', 'redis')
SCRIPT = Path(__file__).resolve()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def write_yaml(path, data):
    path.write_text(yaml.safe_dump(data))
    path.chmod(0o600)
    return str(path)


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def start(stack, command, env, directory, name):
    log = stack.enter_context((directory / (name + '.log')).open('w'))
    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True, cwd=directory)
    stack.callback(stop, process)
    return process


def run(command, env, directory, label):
    with ExitStack() as stack:
        process = start(stack, command, env, directory, label)
        try:
            code = process.wait(timeout=PHASE_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError(label + ': harness deadline exceeded') from None
        if code:
            # Test-local logs only; do not print raw configuration, keys or tokens.
            raise RuntimeError(label + ': subprocess failed with exit ' + str(code))


def wait_for(predicate, label, processes=(), timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(all(p.poll() is None for p in processes), label + ': process exited')
        try:
            if predicate():
                return
        except (requests.RequestException, redis.RedisError, OSError):
            pass
        time.sleep(0.1)
    raise RuntimeError(label + ': readiness deadline exceeded')


def tls_fixture(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable Pebble transport')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    crt, pem = directory / 'transport.pem', directory / 'transport.key'
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pem.chmod(0o600)
    return crt, pem


def worker_cycle(args):
    from certlord.composition import certificate_runtime
    from certlord.classes.certbot_handler import SslCertsCertbotHandler
    from certlord.classes.vault_crawler import SslCertsVaultCrawler
    from certlord.classes.deployer import SslCertsDeployer
    config = yaml.safe_load(args.config.read_text())
    config['credentials'] = yaml.safe_load(Path(config['credentials']).read_text())
    module = certificate_runtime(config, config['modules']['ssl_certs'])
    if args.cycle == 'issue':
        worker = SslCertsCertbotHandler(module, module._redis)
    elif args.cycle == 'crawl':
        worker = SslCertsVaultCrawler(module, module._redis, None)
    else:
        worker = SslCertsDeployer(module, module._redis)
    worker._run()  # Actual production cycle; no background worker or fake backend.


def certificate_checks(data, domain=DOMAIN):
    cert = x509.load_pem_x509_certificate(data['cert'].encode())
    key = serialization.load_pem_private_key(data['key'].encode(), password=None)
    chain = x509.load_pem_x509_certificates(data['chain'].encode())
    require(chain, 'Missing issued chain')
    cert.verify_directly_issued_by(chain[0])
    public = lambda k: k.public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    require(public(cert.public_key()) == public(key.public_key()), 'Issued key mismatch')
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    require(names.get_values_for_type(x509.DNSName) == [domain], 'Unexpected SAN')
    require(cert.not_valid_after_utc > datetime.now(timezone.utc), 'Issued certificate expired')
    return cert


def deploy_job(args):
    config = json.loads(args.job_config.read_text())
    root = Path(config['directory'])
    with (root / 'deployment-starts').open('a') as starts:
        starts.write('started\n')
    if (root / 'hold-deployment').exists():
        (root / 'deployment-held').touch()
        deadline = time.monotonic() + 15
        while (root / 'hold-deployment').exists():
            require(time.monotonic() < deadline, 'Held fixture deployment timed out')
            time.sleep(0.1)
    if (root / 'fail-deployment').exists():
        (root / 'injected-failure-executed').touch()
        return 23
    client = hvac.Client(url=config['vault'], token=config['token'])
    data = client.secrets.kv.v2.read_secret_version(config['secret_path'], raise_on_deleted_version=True)['data']['data']
    cert = certificate_checks(data, config.get('domain', DOMAIN))
    bundle = root / ('bundle-' + str(cert.serial_number))
    bundle.mkdir(mode=0o700, exist_ok=True)
    (bundle / 'fullchain.pem').write_text(data['cert'] + data['chain'])
    (bundle / 'key.pem').write_text(data['key'])
    (bundle / 'key.pem').chmod(0o600)
    temporary = root / 'next-bundle'
    temporary.symlink_to(bundle)
    temporary.replace(root / 'current')
    if (root / 'seal-after-install').exists():
        # Simulate real storage unavailability after the external effect, before
        # CertLord can acknowledge it. This is a disposable Vault only.
        client.sys.seal()
        (root / 'installed-before-vault-seal').touch()
    return 0


class Frontend:
    """Test-only public HTTP-01 frontend; administration remains on loopback."""
    def __init__(self, api):
        self.api, self.reject, self.reads = api, False, 0
        self.hold, self.held = threading.Event(), threading.Event()

    def handler(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                state.reads += 1
                if state.hold.is_set():
                    state.held.set()
                    deadline = time.monotonic() + 30
                    while state.hold.is_set() and time.monotonic() < deadline:
                        time.sleep(0.05)
                if state.reject:
                    code, body = 404, b''
                else:
                    response = requests.get(state.api + self.path, timeout=5)
                    code, body = response.status_code, response.content
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler


class VaultFaultProxy:
    """Loopback-only fixture: accept requests, then withhold every response."""
    def __init__(self, backend):
        self.backend = backend
        self.blocked = threading.Event()
        self.observed = threading.Event()
        self.release = threading.Event()

    def handler(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def forward(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if state.blocked.is_set():
                    state.observed.set()
                    state.release.wait(30)
                    # Never forward a timed-out mutation after fault recovery.
                    self.close_connection = True
                    return
                headers = {name: self.headers[name] for name in
                           ('Content-Type', 'X-Vault-Token') if name in self.headers}
                response = requests.request(self.command, state.backend + self.path,
                                            headers=headers, data=body, timeout=5)
                self.send_response(response.status_code)
                self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
                self.send_header('Content-Length', str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_LIST = forward

        return Handler


def http_thread(stack, server):
    stack.callback(server.server_close)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(thread.join, 5)
    stack.callback(server.shutdown)


def served_fingerprint(port, ca, domain=DOMAIN):
    context = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=domain) as tls:
            cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            return cert.fingerprint(hashes.SHA256()).hex()


def graceful_stop(process, label, timeout=10):
    """No kill fallback can count as a successful graceful-shutdown assertion."""
    require(process.poll() is None, label + ': daemon exited before stop')
    children = psutil.Process(process.pid).children(recursive=True)
    started = time.monotonic()
    process.send_signal(signal.SIGTERM)
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(label + ': graceful shutdown deadline exceeded') from None
    require(code == 0, label + ': daemon did not exit cleanly')
    require(time.monotonic() - started < timeout, label + ': shutdown exceeded budget')
    require(all(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE for child in children),
            label + ': local child survived graceful shutdown')


def authenticated_api_checks(config, directory, stack, env, phase, report):
    protected = copy.deepcopy(config)
    port = free_port()
    url = 'http://127.0.0.1:%d' % port
    password = secrets.token_urlsafe(24)
    # SHA htpasswd is only a disposable legacy Basic fixture, not password-storage guidance.
    encoded = '{SHA}' + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
    passwd = directory / 'fixture.htpasswd'
    passwd.write_text(''.join(name + ':' + encoded + '\n' for name in ('operator', 'reader', 'denied')))
    passwd.chmod(0o600)
    protected['general'].update(listen_port=port, auth_basic='CertLord fixture', auth_basic_file=str(passwd))
    protected['api_authentication'] = {'backend': 'httpdis', 'permissions': {
        'operator': ['read', 'write', 'deploy', 'challenge'], 'reader': ['read']}}
    path = write_yaml(directory / 'protected.yml', protected)
    process = start(stack, ['certlord', '-f', '-c', path, '-p', str(directory / 'protected.pid'),
        '--logfile', str(directory / 'protected-daemon.log')], env, directory, 'protected')
    index = url + '/api/certificates'
    wait_for(lambda: requests.get(index, auth=('operator', password), timeout=1).ok,
             'Authenticated CertLord', [process])
    for credentials in (None, ('operator', 'wrong'), ('unknown', password)):
        response = requests.get(index, auth=credentials, timeout=5)
        require(response.status_code == 401, 'Missing/invalid credentials did not return 401')
    require(requests.get(index, headers={'HTTP_AUTH_USER': 'operator', 'X-Auth-User': 'operator'},
                         timeout=5).status_code == 401, 'Spoofed identity header bypassed authentication')
    require(requests.get(index, auth=('denied', password), timeout=5).status_code == 403,
            'Authenticated identity without permission was accepted')
    require(requests.get(index, auth=('reader', password), timeout=5).ok, 'Reader cannot read')
    for route, payload in (('/api/certificates', {'domains': [DOMAIN]}),
                           ('/api/ssl-certs/save', {}), ('/api/ssl-certs/deploy', {})):
        require(requests.post(url + route, json=payload, auth=('reader', password), timeout=5).status_code == 403,
                'Read-only identity could mutate certificate state')
    require(requests.post(url + '/api/ssl-certs/deploy', auth=('operator', password), timeout=5).ok,
            'Authorized deployment trigger rejected')
    require(requests.delete(url + '/api/certificates/273c46a7-9982-4e1f-a86a-8ee42ea598df', json={'domains': []},
                          auth=('operator', password), timeout=5).ok, 'Authorized write rejected')
    phase('httpdis-basic-authentication-and-operation-permissions')
    challenge = url + '/.well-known/acme-challenge/' + 'A' * 43
    for credentials, expected in ((None, 401), (('reader', password), 403)):
        require(requests.put(challenge, json='fixture.proof', auth=credentials, timeout=5).status_code == expected,
                'Challenge mutation was not protected')
    require(requests.put(challenge, json='fixture.proof', auth=('operator', password), timeout=5).ok,
            'Authorized challenge creation rejected')
    response = requests.get(challenge, timeout=5)
    require(response.ok and response.text == 'fixture.proof', 'Public challenge GET requires credentials or changed data')
    require(requests.delete(challenge, auth=('reader', password), timeout=5).status_code == 403,
            'Read-only identity deleted challenge')
    require(requests.delete(challenge, auth=('operator', password), timeout=5).ok,
            'Authorized challenge cleanup rejected')
    missing = requests.get(challenge, timeout=5)
    require(missing.status_code == 404 and missing.headers['Content-Type'].startswith('application/json'),
            'Missing challenge did not return a JSON 404')
    require(missing.headers.get('Cache-Control') == 'no-store', 'Missing challenge response is cacheable')
    for invalid in ({'invalid': 'payload'}, 'fixture.proof\n'):
        rejected = requests.put(challenge, json=invalid, auth=('operator', password), timeout=5)
        require(rejected.status_code == 400, 'Invalid challenge payload did not return 400')
    require(requests.get(challenge, timeout=5).status_code == 404,
            'Rejected challenge payload was persisted')
    rejected = requests.post(url + '/api/ssl-certs/save', json={}, auth=('operator', password), timeout=5)
    require(rejected.status_code == 400, 'Invalid certificate payload did not return 400')
    phase('http-invalid-data-is-400-missing-challenge-is-404-without-mutation')
    require(requests.post(url + '/api/certificates/import', json={}, auth=('reader', password), timeout=5).status_code == 403,
            'Read-only identity could import certificate material')
    require(requests.post(url + '/api/certificates/import', json={}, auth=('operator', password), timeout=5).status_code == 400,
            'Authorized invalid import did not fail validation')
    replace_route = url + '/api/certificates/273c46a7-9982-4e1f-a86a-8ee42ea598df/material'
    require(requests.put(replace_route, json={}, auth=('reader', password), timeout=5).status_code == 403,
            'Read-only identity could replace certificate material')
    require(requests.put(replace_route, json={}, auth=('operator', password), timeout=5).status_code == 400,
            'Replacement without version did not fail validation')
    for suffix, content_type in (('observations', 'application/json'), ('metrics', 'text/plain')):
        endpoint = index + '/' + suffix
        for credentials, expected in ((None, 401), (('reader', 'wrong'), 401),
                                      (('denied', password), 403)):
            require(requests.get(endpoint, auth=credentials, timeout=5).status_code == expected,
                    'Supervision endpoint bypassed read authentication')
        response = requests.get(endpoint, auth=('reader', password), timeout=5)
        require(response.ok and response.headers['Content-Type'].startswith(content_type),
                'Authenticated supervision response has wrong format')
        require(response.headers.get('Cache-Control') == 'no-store', 'Supervision response is cacheable')
    for route, expected in (('/api/health/live',200),('/api/health/ready',503),
                            ('/api/operations',200),('/api/operations/metrics',200)):
        endpoint = url + route
        require(requests.get(endpoint, timeout=5).status_code == 401, 'Operational route is unauthenticated')
        require(requests.get(endpoint, auth=('denied',password), timeout=5).status_code == 403,
                'Operational route lacks read authorization')
        response = requests.get(endpoint, auth=('reader',password), timeout=5)
        require(response.status_code == expected, 'Operational route has wrong readiness/status')
        require(response.headers.get('Cache-Control') == 'no-store', 'Operational route is cacheable')
    phase('authenticated-operational-routes-api-only-is-not-ready')
    phase('supervision-read-authentication-and-response-formats')
    phase('authenticated-challenge-mutation-with-public-get')
    # Review the installed framework boundary without claiming RFC conformance.
    # Released framework dependencies must satisfy these selected HTTP contracts.
    inventory_before = requests.get(index, auth=('operator', password), timeout=5).json()
    json_marker = 'SYNTHETIC_JSON_REVIEW_MARKER'
    validation_marker = '!SYNTHETIC PRIVATE VALUE!'
    boundary = {'responses': {}, 'conformance': 'review-required'}
    report['http_boundary_review'] = boundary
    probes = (
        ('malformed_json_authenticated', 'POST', index, ('operator', password),
         {'Content-Type': 'application/json'}, '{"value":"' + json_marker + '"', 400),
        ('malformed_json_unauthenticated', 'POST', index, None,
         {'Content-Type': 'application/json'}, '{"value":"' + json_marker + '"', 401),
        ('invalid_utf8_authenticated', 'POST', index, ('operator', password),
         {'Content-Type': 'application/json'}, b'\xff', 400),
        ('unknown_url_authenticated', 'GET', url + '/api/no-such-route', ('operator', password), {}, None, 404),
        ('unknown_url_unauthenticated', 'GET', url + '/api/no-such-route', None, {}, None, 404),
        ('wrong_method_authenticated', 'PATCH', index, ('operator', password),
         {'Content-Type': 'application/json'}, '{}', 405),
        ('wrong_method_unauthenticated', 'PATCH', index, None,
         {'Content-Type': 'application/json'}, '{}', 405),
        ('unsupported_content_type_authenticated', 'POST', index, ('operator', password),
         {'Content-Type': 'text/plain'}, json_marker, 415),
        ('invalid_domain_authenticated', 'POST', index, ('operator', password),
         {'Content-Type': 'application/json'}, json.dumps({'domains': [validation_marker]}), 400),
    )
    for label, method, endpoint, auth, headers, body, expected_status in probes:
        result = requests.request(method, endpoint, auth=auth, headers=headers, data=body, timeout=5)
        boundary['responses'][label] = {'status': result.status_code,
            'json': result.headers.get('Content-Type', '').startswith('application/json'),
            'allow': result.headers.get('Allow')}
        require(result.status_code == expected_status, 'Unexpected framework response: %s (%s)' % (label, result.status_code))
        require(boundary['responses'][label]['json'], 'Framework error is not JSON: ' + label)
        if label.startswith('wrong_method_'):
            require(result.headers.get('Allow') == 'GET, POST', 'Framework Allow methods mismatch')
        require(json_marker not in result.text and validation_marker not in result.text,
                'Framework response disclosed synthetic body values: ' + label)

    require(requests.get(index, auth=('operator', password), timeout=5).json() == inventory_before,
            'Rejected framework probes changed inventory')
    graceful_stop(process, 'Protected API')
    log = (directory / 'protected-daemon.log').read_text()
    boundary['malformed_json_marker_in_log'] = json_marker in log
    boundary['validation_marker_in_log'] = validation_marker in log
    require(not boundary['malformed_json_marker_in_log'], 'Malformed JSON body leaked into daemon log')
    require(not boundary['validation_marker_in_log'], 'Validation value leaked into daemon log')
    boundary['conformance'] = 'selected-contracts-passed'
    phase('framework-boundary-review-records-statuses-and-preserves-inventory')
    return boundary


def approle_checks(vault, vault_url, source, phase):
    """Exercise production composition/storage against real scoped Vault policies."""
    from certlord.composition import certificate_store
    from certlord.ports.certificates import StorageError
    role = 'certlord-fixture'
    prefix = 'approle-fixture'
    policy = (source / 'etc/certlord/vault-policy.hcl.example').read_text()
    policy = policy.replace('certlord-certificates', prefix)
    vault.sys.create_or_update_policy(role, policy)
    vault.sys.enable_auth_method('approle')
    vault.auth.approle.create_or_update_approle(role, token_policies=[role],
        token_no_default_policy=True, token_ttl='60s', token_max_ttl='300s', secret_id_ttl='300s')
    role_id = vault.auth.approle.read_role_id(role)['data']['role_id']
    first_secret = vault.auth.approle.generate_secret_id(role)['data']['secret_id']
    config = {'credentials': {'vault': {'uri': vault_url, 'key_name': prefix, 'token': '-',
                                       'role_id': role_id, 'secret_id': first_secret}}}
    repository = certificate_store(config)
    material = {'cert': 'fixture-only', 'status': 'generated'}
    repository.put(CERTIFICATE_ID, DOMAIN, material)
    require(repository.get(CERTIFICATE_ID, DOMAIN) == material, 'AppRole cannot read its certificate')
    require(CERTIFICATE_ID in repository.list_certificate_ids() and DOMAIN in repository.list_domains(CERTIFICATE_ID),
            'AppRole cannot list its own certificate scope')
    repository.update(CERTIFICATE_ID, DOMAIN, {'status': 'processing'})
    snapshot, revision = repository.get_versioned(CERTIFICATE_ID, DOMAIN)
    require(snapshot['status'] == 'processing', 'AppRole cannot patch its certificate')
    repository.replace_if_version(CERTIFICATE_ID, DOMAIN, revision, dict(snapshot, status='deployed'))
    require(repository.get(CERTIFICATE_ID, DOMAIN)['status'] == 'deployed', 'AppRole CAS write failed')
    outside_path = 'outside-approle/6ff9418a-a4d7-5964-b0a3-78f920426989/' + DOMAIN
    vault.secrets.kv.v2.create_or_update_secret(outside_path, secret={'marker': 'untouched'})
    foreign_config = copy.deepcopy(config)
    foreign_config['credentials']['vault']['key_name'] = 'outside-approle'
    foreign = certificate_store(foreign_config)
    for operation in (lambda: foreign.get(CERTIFICATE_ID, DOMAIN),
                      lambda: foreign.put(CERTIFICATE_ID, DOMAIN, {'marker': 'changed'}),
                      lambda: foreign.delete(CERTIFICATE_ID, DOMAIN), foreign.list_certificate_ids):
        try:
            operation()
        except StorageError:
            pass
        else:
            raise RuntimeError('Scoped AppRole accessed an unauthorized certificate prefix')
    require(vault.secrets.kv.v2.read_secret_version(outside_path)['data']['data'] == {'marker': 'untouched'},
            'Denied AppRole mutation changed another scope')
    try:
        repository._session.client().sys.list_policies()
    except hvac.exceptions.Forbidden:
        pass
    else:
        raise RuntimeError('Certificate AppRole unexpectedly has policy administration access')
    phase('approle-scoped-storage-and-out-of-scope-denial')
    old_token = repository._session.client().token
    vault.auth.token.revoke(old_token)
    require(repository.get(CERTIFICATE_ID, DOMAIN)['status'] == 'deployed',
            'AppRole did not recover after token revocation')
    require(repository._session.client().token != old_token, 'Revoked AppRole token was reused')
    phase('approle-reauthenticates-after-token-revocation')
    # Secret-ID revocation does not itself revoke tokens already issued from it.
    active_token = repository._session.client().token
    vault.auth.approle.destroy_secret_id(role, first_secret)
    vault.auth.token.revoke(active_token)
    try:
        repository.get(CERTIFICATE_ID, DOMAIN)
    except StorageError:
        pass
    else:
        raise RuntimeError('Revoked AppRole credentials did not fail closed')
    rotated = copy.deepcopy(config)
    rotated['credentials']['vault']['secret_id'] = vault.auth.approle.generate_secret_id(role)['data']['secret_id']
    replacement = certificate_store(rotated)
    require(replacement.get(CERTIFICATE_ID, DOMAIN)['status'] == 'deployed', 'Rotated Secret ID could not recover storage')
    replacement.delete(CERTIFICATE_ID, DOMAIN)
    require_destroyed_certificate(vault, prefix + '/' + CERTIFICATE_ID + '/' + DOMAIN)
    require(replacement.get(CERTIFICATE_ID, DOMAIN) == {}, 'Scoped AppRole cannot remove certificate material')
    vault.secrets.kv.v2.delete_metadata_and_all_versions(outside_path)
    phase('approle-secret-id-revocation-and-explicit-replacement')


def require_destroyed_certificate(vault, path):
    latest = vault.secrets.kv.v2.read_secret_version(path)['data']['data']
    require(latest == {'status': 'removed'}, 'Removal retained certificate material')
    metadata = vault.secrets.kv.v2.read_secret_metadata(path)['data']
    # Only material-free deletion markers may remain readable in history.
    for number, details in metadata['versions'].items():
        if details['destroyed']:
            continue
        data = vault.secrets.kv.v2.read_secret_version(path, version=int(number))['data']['data']
        require(data in ({'status': 'delete'}, {'status': 'removed'}),
                'Removal left a readable historical certificate version')
    return metadata['current_version']


def save_coordination_checks(vault, config, material, phase):
    """Controlled interleavings with real Vault/Redis, no replacement storage mocks."""
    from certlord.composition import certificate_runtime, certificate_store
    from certlord.ports.certificates import StorageError
    from certlord.services.certificates import CertificateConflict, CertificateNotFound
    conf = copy.deepcopy(config)
    conf['credentials'] = yaml.safe_load(Path(conf['credentials']).read_text())
    conf['credentials']['vault']['key_name'] = 'save-fixture'
    runtime = certificate_runtime(conf, conf['modules']['ssl_certs'])
    original_sites = runtime.get_certificate_ids_for_domain(DOMAIN)['certificate_ids']
    certificate_ids = ['9de48d63-f155-51ba-88ef-e65a876e7de7', 'f7cfb052-81df-5f4e-9d58-427cf0515d00']
    seed = {'cert': '', 'key': '', 'chain': '', 'status': 'processing', 'issuance_complete': False}
    payload = {key: material[key] for key in ('cert', 'key', 'chain')}
    payload['domain'] = DOMAIN
    try:
        runtime.set_certificate_ids_for_domain(DOMAIN, certificate_ids)
        for certificate_id in certificate_ids:
            runtime._create_certificate(certificate_id, DOMAIN, data=seed)
        obsolete = runtime.service.begin_issuance(DOMAIN)
        attempt = runtime.service.begin_issuance(DOMAIN)
        before_attempt = [runtime.certificate_snapshot(certificate_id, DOMAIN) for certificate_id in certificate_ids]
        try:
            runtime.service.save(payload, obsolete)
        except CertificateConflict:
            pass
        else:
            raise RuntimeError('Superseded issuance saved shared material')
        require([runtime.certificate_snapshot(certificate_id, DOMAIN) for certificate_id in certificate_ids] == before_attempt,
                'Rejected issuance changed a shared record')
        # New runtime and Vault session must read persisted attempt identity.
        runtime = certificate_runtime(conf, conf['modules']['ssl_certs'])
        require(all(runtime.get_certificate(certificate_id, DOMAIN)['issuance_id'] == attempt for certificate_id in certificate_ids),
                'Restart lost issuance identity')
        phase('issuance-supersession-preserves-shared-records-and-survives-new-runtime')
        # Both records can be read; only the first can be written.
        policy = '''path "auth/token/lookup-self" { capabilities = ["read"] }
path "secret/data/save-fixture/*" { capabilities = ["read"] }
path "secret/data/save-fixture/9de48d63-f155-51ba-88ef-e65a876e7de7/*" { capabilities = ["read", "create", "update"] }
path "secret/metadata/save-fixture" { capabilities = ["list"] }
path "secret/metadata/save-fixture/*" { capabilities = ["list"] }
'''
        vault.sys.create_or_update_policy('partial-save-fixture', policy)
        token = vault.auth.token.create(policies=['partial-save-fixture'],
            no_default_policy=True, ttl='60s')['auth']['client_token']
        limited = copy.deepcopy(conf)
        limited['credentials']['vault']['token'] = token
        root_store = runtime._store
        runtime._store = certificate_store(limited)
        try:
            runtime.service.save(payload, attempt)
        except StorageError:
            pass
        else:
            raise RuntimeError('Partial save unexpectedly succeeded')
        require(runtime.evt_tcrawler.is_set(), 'Partial save did not wake crawler')
        first, first_version = root_store.get_versioned('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN)
        require(first['cert'] == payload['cert'] and first['status'] == 'generated',
                'First accepted certificate_id save was lost')
        require(root_store.get('f7cfb052-81df-5f4e-9d58-427cf0515d00', DOMAIN)['status'] == 'processing',
                'Denied certificate_id was modified')
        vault.auth.token.revoke(token)
        runtime._store = root_store
        # Simulate deployment of the first accepted certificate_id before the API retry.
        runtime.mark_deployed('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN, (first, first_version))
        deployed, deployed_version = root_store.get_versioned('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN)
        runtime.service.save(payload, attempt)
        require(root_store.get_versioned('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN) == (deployed, deployed_version),
                'Retry rewrote an already deployed identical certificate')
        require(root_store.get('f7cfb052-81df-5f4e-9d58-427cf0515d00', DOMAIN)['cert'] == payload['cert'],
                'Retry failed to finish the previously denied certificate_id')
        phase('partial-multisite-save-retains-success-and-retry-preserves-deployed-copy')
        try:
            runtime.service.save(dict(payload, cert='different'), attempt)
        except CertificateConflict:
            pass
        else:
            raise RuntimeError('Completed issuance accepted different material')
        phase('completed-issuance-replay-cannot-change-accepted-material')
        # Persist removal after preflight and before the first CAS, as another caller could.
        root_store.update('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN, seed)
        original_save = runtime.save_certificate
        def remove_then_save(certificate_id, domain, data, snapshot):
            root_store.update(certificate_id, domain, {'status': 'delete'})
            return original_save(certificate_id, domain, data, snapshot)
        runtime.save_certificate = remove_then_save
        try:
            runtime.service.save(payload, attempt)
        except CertificateConflict:
            pass
        else:
            raise RuntimeError('Save overwrote concurrent removal')
        finally:
            runtime.save_certificate = original_save
        require(root_store.get('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN)['status'] == 'delete',
                'Conflicting save erased removal marker')
        phase('save-cas-rejects-removal-after-preflight')
        # A stale reverse association must not recreate a physically deleted record.
        root_store.delete('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN)
        before = root_store.get_versioned('f7cfb052-81df-5f4e-9d58-427cf0515d00', DOMAIN)
        try:
            runtime.service.save(payload, attempt)
        except CertificateNotFound:
            pass
        else:
            raise RuntimeError('Stale association recreated a deleted certificate')
        require(root_store.get('9de48d63-f155-51ba-88ef-e65a876e7de7', DOMAIN) == {} and root_store.get_versioned('f7cfb052-81df-5f4e-9d58-427cf0515d00', DOMAIN) == before,
                'Missing-target preflight changed managed certificates')
        phase('save-rejects-stale-association-without-recreating-deleted-record')
    finally:
        runtime.set_certificate_ids_for_domain(DOMAIN, original_sites)
        for certificate_id in certificate_ids:
            vault.secrets.kv.v2.delete_metadata_and_all_versions('save-fixture/' + certificate_id + '/' + DOMAIN)


def exercise(args, directory, stack, report):
    global CERTIFICATE_ID, SECRET_PATH
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('PEBBLE_', 'CBT_HTTPREQ_', 'ACME_HTTP_CONNECTOR_',
                                'CERTLORD_', 'AUTON_', 'AUTOND_', 'VAULT_'))}
    env['NO_PROXY'] = 'localhost,127.0.0.1'
    if args.systemd_scheduler:
        # Direct fixture daemons stay root; the installed unit keeps its own account.
        env.update(CERTLORD_USER='root', CERTLORD_GROUP='root')
    # Tools/daemons and certificates exist only for this invocation.
    redis_port, vault_port, api_port, auton_port = [free_port() for _ in range(4)]
    api, vault_url, auton_url = ['http://127.0.0.1:%d' % p for p in (api_port, vault_port, auton_port)]
    redis_process = start(stack, ['redis-server', '--bind', '127.0.0.1', '--port', str(redis_port),
        '--save', '', '--appendonly', 'no', '--dir', str(directory)], env, directory, 'redis')
    vault_config = directory / 'vault.json'
    vault_config.write_text(json.dumps({
        'storage': {'file': {'path': str(directory / 'vault-data')}},
        'listener': {'tcp': {'address': '127.0.0.1:%d' % vault_port, 'tls_disable': True}},
        'api_addr': vault_url, 'disable_mlock': True}))
    vault_process = start(stack, [str(args.tools / 'vault'), 'server',
        '-config=' + str(vault_config)], env, directory, 'vault')
    pending = redis.Redis(host='127.0.0.1', port=redis_port, db=1, decode_responses=True)
    challenges = redis.Redis(host='127.0.0.1', port=redis_port, db=0)
    wait_for(pending.ping, 'Redis', [redis_process])
    wait_for(lambda: requests.get(vault_url + '/v1/sys/health', timeout=1).status_code == 501,
             'Uninitialized disposable Vault', [vault_process])
    vault = hvac.Client(url=vault_url, timeout=10)
    initialization = vault.sys.initialize(secret_shares=1, secret_threshold=1)
    unseal_key = initialization['keys_base64'][0]
    token = initialization['root_token']
    vault.token = token
    vault.sys.submit_unseal_key(unseal_key)
    vault.sys.enable_secrets_engine('kv', path='secret', options={'version': '2'})
    require(vault.is_authenticated(), 'Vault fixture authentication failed')
    # Initial credentials stay only in this temporary fixture, never in evidence.

    def unseal_vault():
        vault.sys.submit_unseal_key(unseal_key)
        require(not vault.sys.is_sealed(), 'Disposable Vault recovery failed')

    frontend = Frontend(api)
    front_server = ThreadingHTTPServer(('127.0.0.1', 0), frontend.handler())
    http_thread(stack, front_server)
    tls_cert, tls_key = tls_fixture(directory)
    env.update(PEBBLE_VA_NOSLEEP='1', PEBBLE_AUTHZREUSE='0', PEBBLE_WFE_NONCEREJECT='0',
               REQUESTS_CA_BUNDLE=str(tls_cert))
    acme_port, management_port, dns_port, dns_management = [free_port() for _ in range(4)]
    pebble_config = directory / 'pebble.json'
    pebble_config.write_text(json.dumps({'pebble': {
        'listenAddress': '127.0.0.1:%d' % acme_port,
        'managementListenAddress': '127.0.0.1:%d' % management_port,
        'certificate': str(tls_cert), 'privateKey': str(tls_key),
        'httpPort': front_server.server_port, 'tlsPort': free_port(),
        'retryAfter': {'authz': 1, 'order': 1}}}))
    dns = start(stack, [str(args.tools / 'pebble-challtestsrv'), '-dnsserver', '127.0.0.1:%d' % dns_port,
        '-defaultIPv6', '', '-http01', '', '-https01', '', '-tlsalpn01', '', '-doh', '',
        '-management', '127.0.0.1:%d' % dns_management], env, directory, 'dns')
    ca = start(stack, [str(args.tools / 'pebble'), '-config', str(pebble_config),
        '-dnsserver', '127.0.0.1:%d' % dns_port], env, directory, 'pebble')
    acme_url = 'https://localhost:%d/dir' % acme_port
    wait_for(lambda: requests.get(acme_url, verify=str(tls_cert), timeout=1).ok, 'Pebble', [ca, dns])
    roots = requests.get('https://localhost:%d/roots/0' % management_port, verify=str(tls_cert), timeout=5)
    roots.raise_for_status()
    trust = directory / 'issued-root.pem'
    trust.write_text(roots.text)
    plugin = write_yaml(directory / 'plugin.yml', {'perform': {'uri': api}, 'cleanup': {'uri': api},
        'deploy': {'uri': api, 'path': '/api/ssl-certs/save'}})
    job_config = directory / 'job.json'
    job_config.write_text(json.dumps({'directory': str(directory), 'vault': vault_url, 'token': token}))
    job_config.chmod(0o600)
    job_routes = yaml.safe_load((args.source / 'tests/integration/auton-routes.yml').read_text())
    auton_config = {'general': {'listen_addr': '127.0.0.1', 'listen_port': auton_port,
        'auth_mode': 'anonymous', 'max_workers': 3, 'lock_timeout': 5},
        'modules': job_routes,
        'endpoints': {'deploy-fixture': {'plugin': 'subproc', 'config': {
            'prog': sys.executable, 'args': [str(SCRIPT), 'deploy-job', '--job-config', str(job_config)],
            'timeout': 30, 'disallow-args': True, 'disallow-env': True}}}}
    auton_path = write_yaml(directory / 'auton.yml', auton_config)
    auton = start(stack, ['autond', '-f', '-c', auton_path, '-p', str(directory / 'auton.pid'),
        '--logfile', str(directory / 'auton-daemon.log')], env, directory, 'auton')
    wait_for(lambda: requests.get(auton_url + '/health', timeout=1).ok, 'Auton', [auton])
    creds = write_yaml(directory / 'credentials.yml', {
        'auton': {'uri': auton_url, 'endpoint': 'deploy-fixture'},
        'vault': {'uri': vault_url, 'token': token, 'key_name': 'certlord-fixture'}})
    config = yaml.safe_load((args.source / 'etc/certlord/certlord.yml').read_text())
    config['general'].update(listen_addr='127.0.0.1', listen_port=api_port, server_id=SERVER_ID,
        max_workers=5, lock_timeout=5, redis={
            'letsencrypt': {'url': 'redis://127.0.0.1:%d/0' % redis_port},
            'ssl_certs': {'url': 'redis://127.0.0.1:%d/1' % redis_port}})
    config['credentials'] = creds
    config['api_authentication'] = {'backend': 'local'}
    config['modules']['letsencrypt']['challenge_ttl'] = 30
    modconf = config['modules']['ssl_certs']
    modconf.update(command_timeout=20, process_stop_grace=0.2,
                  allow_dns_resolv={}, expected_caa_records=[], processing_delay=-1,
                  renew_before_expiry=365, max_retries=5)
    # Keep real HTTP safe_init; explicitly schedule worker cycles in the harness.
    modconf['routes']['index']['at_start'] = False
    modconf['routes']['index']['at_stop'] = False
    modconf['certbot'] = {'become': {'enabled': False}, 'args': [
        '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
        '--server', acme_url, '--config-dir', str(directory / 'certbot/config'),
        '--work-dir', str(directory / 'certbot/work'), '--logs-dir', str(directory / 'certbot/logs'),
        '--key-type', 'rsa', '--rsa-key-size', '2048', '--force-renewal',
        '-a', 'certbot-httpreq:auth', '-i', 'certbot-httpreq:installer',
        '--certbot-httpreq:auth-config', plugin, '--certbot-httpreq:installer-config', plugin, 'run']}
    modconf['auton'] = {'receipt_mode': True, 'become': {'enabled': False}, 'search_paths': env['PATH'].split(os.pathsep),
        'args': ['--http-timeout', '5', '--delay', '0.1']}
    config_path = write_yaml(directory / 'certlord.yml', config)
    certlord = start(stack, ['certlord', '-f', '-c', config_path, '-p', str(directory / 'certlord.pid'),
        '--logfile', str(directory / 'certlord-daemon.log')], env, directory, 'certlord')
    wait_for(lambda: requests.get(api + '/api/certificates', timeout=1).ok, 'CertLord', [certlord])

    def cycle(name, label, expect_storage_error=False):
        command = [sys.executable, str(SCRIPT), 'cycle', '--config', config_path, '--cycle', name]
        if expect_storage_error:
            command.append('--expect-storage-error')
        run(command, env, directory, label)

    def stored():
        return vault.secrets.kv.v2.read_secret_version(SECRET_PATH, raise_on_deleted_version=True)['data']['data']

    def phase(name):
        report['passed'].append(name)
        print('PASS: ' + name, flush=True)

    for name in ('save', 'deploy', 'validate', '42', '../other'):
        require(requests.put(api + '/api/certificates/' + name,
                             json={'domains': [DOMAIN]}, timeout=5).status_code == 404,
                'Invalid certificate identity route was accepted')
    require(requests.put(api + '/api/certificates/' + str(uuid.uuid4()),
                         json={'domains': [DOMAIN]}, timeout=5).status_code == 404,
            'PUT created a client-selected UUID')
    require(requests.post(api + '/api/ssl-certs/42', json={'sub_domains': []}, timeout=5).status_code == 404,
            'Legacy numeric route remained enabled')
    require(requests.post(api + '/api/certificates', json={'domains': []}, timeout=5).status_code == 400,
            'Empty certificate creation was accepted')
    phase('uuid-resource-routes-reject-legacy-identities-and-empty-creation')
    approle_checks(vault, vault_url, args.source, phase)
    report['http_boundary_review'] = authenticated_api_checks(config, directory, stack, env, phase, report)

    from certlord.adapters.deployment_lease import DeploymentLease, LeaseLost
    from certlord.adapters.vault_auth import VaultSession, VaultTokenAuth
    from certlord.adapters.vault_store import VaultCertificateStore
    from certlord.ports.certificates import StorageConflict
    from dwho.adapters.redis import DWhoAdapterRedis
    store = VaultCertificateStore(VaultSession(vault_url, VaultTokenAuth(token)), 'cas-fixture')
    store.put(CERTIFICATE_ID, DOMAIN, {'cert': 'old', 'status': 'generated'})
    old, revision = store.get_versioned(CERTIFICATE_ID, DOMAIN)
    store.put(CERTIFICATE_ID, DOMAIN, {'cert': 'new', 'status': 'generated'})
    try:
        store.replace_if_version(CERTIFICATE_ID, DOMAIN, revision, dict(old, status='deployed'))
    except StorageConflict:
        pass
    else:
        raise RuntimeError('Stale Vault acknowledgement was accepted')
    require(store.get(CERTIFICATE_ID, DOMAIN) == {'cert': 'new', 'status': 'generated'},
            'Stale acknowledgement replaced the new certificate')
    store.delete(CERTIFICATE_ID, DOMAIN)
    phase('vault-stale-version-rejected')
    removed_version = require_destroyed_certificate(vault, 'cas-fixture/' + CERTIFICATE_ID + '/' + DOMAIN)
    # The old version 1 used to match a newly recreated record after metadata deletion.
    store.put(CERTIFICATE_ID, DOMAIN, {'cert': 'replacement', 'status': 'generated'})
    replacement, new_version = store.get_versioned(CERTIFICATE_ID, DOMAIN)
    require(new_version > removed_version > revision, 'Vault counter reset on recreation')
    try:
        store.replace_if_version(CERTIFICATE_ID, DOMAIN, revision, dict(old, status='deployed'))
    except StorageConflict:
        pass
    else:
        raise RuntimeError('Old snapshot overwrote a recreated certificate')
    require(store.get(CERTIFICATE_ID, DOMAIN) == replacement, 'Recreated certificate was overwritten')
    phase('vault-removal-recreation-rejects-old-snapshot-with-monotonic-versions')
    store.delete(CERTIFICATE_ID, DOMAIN)
    try:
        store.replace_if_version(CERTIFICATE_ID, DOMAIN, new_version, replacement)
    except StorageConflict:
        pass
    else:
        raise RuntimeError('Old snapshot resurrected a removed certificate')
    require(store.get(CERTIFICATE_ID, DOMAIN) == {} and store.list_domains(CERTIFICATE_ID) == [],
            'Removed markers leaked into managed inventory')
    phase('vault-removed-record-cannot-be-resurrected-by-stale-cas')
    # Refuse historical material destruction after the marker write, then recover.
    store.put(CERTIFICATE_ID, DOMAIN, replacement)
    policy = '''path "auth/token/lookup-self" { capabilities = ["read"] }
path "secret/data/cas-fixture/*" { capabilities = ["read", "create", "update"] }
path "secret/metadata/cas-fixture/*" { capabilities = ["read", "list"] }
'''
    vault.sys.create_or_update_policy('destroy-denied-fixture', policy)
    limited_token = vault.auth.token.create(policies=['destroy-denied-fixture'],
        no_default_policy=True, ttl='60s')['auth']['client_token']
    limited = VaultCertificateStore(VaultSession(vault_url, VaultTokenAuth(limited_token)), 'cas-fixture')
    from certlord.ports.certificates import StorageError
    try:
        limited.delete(CERTIFICATE_ID, DOMAIN)
    except StorageError:
        pass
    else:
        raise RuntimeError('Denied destruction was acknowledged')
    require(store.get(CERTIFICATE_ID, DOMAIN) == {'status': 'delete'}, 'Failed destruction lost retry marker')
    require(DOMAIN in store.list_domains(CERTIFICATE_ID), 'Failed destruction hidden from retry discovery')
    vault.auth.token.revoke(limited_token)
    store.delete(CERTIFICATE_ID, DOMAIN)
    require_destroyed_certificate(vault, 'cas-fixture/' + CERTIFICATE_ID + '/' + DOMAIN)
    phase('vault-destroy-denial-preserves-visible-retry-and-recovery-erases-material')
    from concurrent.futures import ThreadPoolExecutor
    from certlord.adapters.pending import PendingCertificates
    index_domain = 'index.example.test'
    index_adapter = PendingCertificates(DWhoAdapterRedis(config, prefix='ssl_certs'))
    index_adapter.set_certificate_ids_for_domain(index_domain, ['c90e8c89-5850-5665-887f-bd666e37fc5b'])
    def mutate_index(change):
        certificate_id, present = change
        return PendingCertificates(DWhoAdapterRedis(config, prefix='ssl_certs')).change_certificate_id(
            index_domain, certificate_id, present)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(mutate_index, [(str(uuid.uuid5(uuid.NAMESPACE_DNS, 'concurrent-' + str(certificate_id))), True) for certificate_id in range(12)]))
    require(set(index_adapter.get_certificate_ids_for_domain(index_domain)['certificate_ids']) == {'c90e8c89-5850-5665-887f-bd666e37fc5b'} | {str(uuid.uuid5(uuid.NAMESPACE_DNS, 'concurrent-' + str(certificate_id))) for certificate_id in range(12)},
            'Concurrent additions lost certificate_id associations')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(mutate_index, [(str(uuid.uuid5(uuid.NAMESPACE_DNS, 'concurrent-' + str(certificate_id))), bool(certificate_id % 2)) for certificate_id in range(12)]))
    require(set(index_adapter.get_certificate_ids_for_domain(index_domain)['certificate_ids']) == {'c90e8c89-5850-5665-887f-bd666e37fc5b'} | {str(uuid.uuid5(uuid.NAMESPACE_DNS, 'concurrent-' + str(certificate_id))) for certificate_id in range(1, 12, 2)},
            'Concurrent mutations changed unrelated associations')
    phase('redis-atomic-certificate_id-mutations-preserve-concurrent-associations')
    for certificate_id in index_adapter.get_certificate_ids_for_domain(index_domain)['certificate_ids']:
        index_adapter.change_certificate_id(index_domain, certificate_id, False)
    require(index_adapter.get_certificate_ids_for_domain(index_domain)['certificate_ids'] == [], 'Empty certificate_ids did not remain a JSON array')
    index_adapter.change_certificate_id(index_domain, '6ff9418a-a4d7-5964-b0a3-78f920426989', True)
    index_adapter.change_certificate_id(index_domain, '6ff9418a-a4d7-5964-b0a3-78f920426989', True)
    require(index_adapter.get_certificate_ids_for_domain(index_domain)['certificate_ids'] == ['6ff9418a-a4d7-5964-b0a3-78f920426989'], 'Repeated add duplicated certificate_id')
    phase('redis-certificate_id-mutation-replay-and-empty-array-shape')
    adapter = DWhoAdapterRedis(config, prefix='ssl_certs')
    owner = DeploymentLease(adapter, SERVER_ID, 0.4)
    contender = DeploymentLease(adapter, SERVER_ID, 1)
    require(owner.acquire() and not contender.acquire(), 'Deployment lease permitted two owners')
    # Simulate a crashed owner: no release or renewal; Redis must recover it.
    wait_for(contender.acquire, 'Abandoned deployment lease expiry')
    require(not owner.release(), 'Expired owner removed successor lease')
    try:
        owner.acknowledge(SERVER_ID, 'nonexistent-fixture')
    except LeaseLost:
        pass
    else:
        raise RuntimeError('Expired owner acknowledged work')
    require(contender.renew(), 'Successor lost lease after stale owner action')
    contender.release()
    phase('redis-exclusive-lease-expiry-and-owner-check')

    response = requests.post(api + '/api/certificates', json={'domains': [DOMAIN]}, timeout=10)
    require(response.ok, 'Create request rejected: HTTP ' + str(response.status_code))
    CERTIFICATE_ID = response.json()['certificate_id']
    operation_id = response.json().get('operation_id')
    require(uuid.UUID(operation_id).version == 4 and operation_id != CERTIFICATE_ID,
            'Creation omitted a separate server-generated operation ID')
    require(uuid.UUID(CERTIFICATE_ID).version == 4, 'Server did not generate a UUID4')
    SECRET_PATH = 'certlord-fixture/' + CERTIFICATE_ID + '/' + DOMAIN
    from concurrent.futures import ThreadPoolExecutor
    from certlord.services.identity_definition import identity_definition, identity_fingerprint
    def repeat_creation(_):
        for _attempt in range(20):
            result = requests.post(api + '/api/certificates', json={'domains': [DOMAIN.upper()]}, timeout=10)
            if result.status_code != 503:
                break
            time.sleep(0.05)
        require(result.ok, 'Repeated creation failed')
        require(result.json().get('operation_id') == operation_id, 'Replay replaced stored operation ID')
        return result.json()['certificate_id']
    with ThreadPoolExecutor(max_workers=4) as executor:
        require(set(executor.map(repeat_creation, range(8))) == {CERTIFICATE_ID},
                'Repeated creation allocated a different UUID')
    definition = identity_definition([DOMAIN])
    digest = identity_fingerprint(definition)
    identity_path = 'certlord-fixture/_identities/' + digest
    indexed = vault.secrets.kv.v2.read_secret_version(identity_path)['data']['data']
    require(indexed == {'certificate_id': CERTIFICATE_ID, 'definition': definition, 'sha256': digest},
            'Canonical identity sources were not persisted correctly')
    require(stored()['identity_sha256'] == digest, 'Certificate omitted its identity fingerprint')
    # A fresh storage session must retrieve the same reservation without allocating another UUID.
    fresh = VaultCertificateStore(VaultSession(vault_url, VaultTokenAuth(token)), 'certlord-fixture')
    require(fresh.reserve_identity(definition, str(uuid.uuid4())) == CERTIFICATE_ID,
            'Fresh storage session lost the identity reservation')
    race_definition = identity_definition(['reservation.example.test'])
    def reserve(_):
        independent = VaultCertificateStore(VaultSession(vault_url, VaultTokenAuth(token)), 'identity-race-fixture')
        return independent.reserve_identity(race_definition, str(uuid.uuid4()))
    with ThreadPoolExecutor(max_workers=4) as executor:
        reservations = set(executor.map(reserve, range(8)))
    require(len(reservations) == 1, 'Atomic first reservation allocated multiple UUIDs')
    phase('sha256-canonical-identity-concurrent-replay-and-fresh-session')
    deployment_config = json.loads(job_config.read_text())
    deployment_config['secret_path'] = SECRET_PATH
    job_config.write_text(json.dumps(deployment_config))
    cli_env = dict(env, CERTLORD_API_URL=api)

    def client_command(*command):
        return subprocess.run(['certlord', *command], env=cli_env, cwd=directory,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)

    listed = client_command('list', '--json')
    require(listed.returncode == 0 and any(item['certificate_id'] == CERTIFICATE_ID
            for item in json.loads(listed.stdout)), 'Installed CLI inventory did not retain full UUID')
    for selector in (DOMAIN, CERTIFICATE_ID, CERTIFICATE_ID[:8]):
        shown = client_command('show', selector, '--json')
        require(shown.returncode == 0 and json.loads(shown.stdout)['certificate_id'] == CERTIFICATE_ID,
                'Installed CLI selector did not resolve the managed certificate')
    require(client_command('tui').returncode != 0, 'TUI entered a non-interactive command')
    require(requests.put(api + '/api/certificates/' + CERTIFICATE_ID,
                        json={'domains': ['other.example.test']}, timeout=5).status_code == 409,
            'UUID was reassigned to another domain')
    phase('generated-uuid-installed-cli-selectors-and-noninteractive-tui-rejection')
    require(pending.exists('cert:' + CERTIFICATE_ID), 'Pending request not persisted')
    # Exercise the explicit TUI against the real API through a pseudo-terminal.
    import pty
    import select
    master, slave = pty.openpty()
    interactive = subprocess.Popen(['certlord', 'tui'], env=dict(cli_env, TERM='xterm'),
        cwd=directory, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    try:
        output = b''
        deadline = time.monotonic() + 10
        while DOMAIN.encode() not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                output += os.read(master, 65536)
        require(DOMAIN.encode() in output, 'TUI did not display certificate domain')
        os.write(master, b'\n')
        deadline = time.monotonic() + 5
        while CERTIFICATE_ID.encode() not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                output += os.read(master, 65536)
        require(CERTIFICATE_ID.encode() in output, 'TUI details omitted full UUID')
        os.write(master, b'qq')
        require(interactive.wait(timeout=5) == 0, 'TUI did not exit cleanly')
    finally:
        if interactive.poll() is None:
            interactive.kill()
            interactive.wait(timeout=5)
        os.close(master)
    phase('explicit-tui-domain-list-full-uuid-details-and-clean-exit')
    cycle('issue', 'issue')
    data = stored()
    require(data['status'] == 'generated', 'Issuance did not reach generated state')
    require(data.get('operation_id') == operation_id and data.get('issuance_id') != operation_id,
            'Issuance lost operation correlation or exposed callback identity')
    first = certificate_checks(data)
    require(frontend.reads > 0, 'ACME did not read HTTP-01 through frontend')
    require(challenges.dbsize() == 0, 'Successful issuance left challenge keys')
    phase('real-http01-issued-stored-cleaned')
    response = requests.get(api + '/api/certificates/observations', timeout=10)
    require(response.ok, 'ACME observation unavailable')
    observation = next(item for item in response.json()['certificates'] if item['certificate_id'] == CERTIFICATE_ID)
    leaf = x509.load_pem_x509_certificate(data['cert'].encode())
    require(observation['origin'] == 'acme' and observation['renewal_owner'] == 'acme'
            and observation['not_after_timestamp_seconds'] == leaf.not_valid_after_utc.timestamp(),
            'ACME observation does not match stored certificate')
    require('PRIVATE KEY' not in response.text and data['key'] not in response.text,
            'Supervision exposed certificate material')
    phase('acme-expiry-observation-matches-stored-leaf')

    from certlord.classes.config import ISSUANCE_HEADER
    callback_data = {key: stored()[key] for key in ('cert', 'key', 'chain')}
    callback_data['domain'] = DOMAIN
    accepted = stored()
    for headers in ({}, {ISSUANCE_HEADER: '0' * 64}):
        response = requests.post(api + '/api/ssl-certs/save', json=callback_data, headers=headers, timeout=10)
        require(response.status_code == 409, 'HTTP save accepted missing/stale issuance identity')
        require(stored() == accepted, 'Rejected callback changed stored certificate')
    response = requests.post(api + '/api/ssl-certs/save', json=callback_data,
                             headers={ISSUANCE_HEADER: accepted['issuance_id']}, timeout=10)
    require(response.ok and stored() == accepted, 'Identical issuance replay was not idempotent')
    phase('real-connector-identity-and-http-stale-callback-rejection')
    cycle('crawl', 'queue-first')
    require(pending.scard(SERVER_ID) == 1, 'Crawler did not queue exactly one deployment')
    queued = pending.smembers(SERVER_ID)
    cycle('crawl', 'queue-repeat')
    require(pending.smembers(SERVER_ID) == queued, 'Repeated crawler duplicated deployment')
    phase('repeated-crawler-deduplicated')
    operation_response = requests.get(api + '/api/operations', timeout=10)
    require(operation_response.ok and operation_response.json()['deployment_entries'] == len(queued),
            'Operations endpoint does not observe real pending deployment queue')
    require(operation_response.json()['deployment_oldest_age_seconds'] is not None,
            'Pending deployment age is missing')
    phase('operational-queue-observation-matches-real-redis')

    pending_before_seal = {key: pending.hgetall(key) for key in queued}
    issuance_before_seal = pending.get('cert:' + CERTIFICATE_ID)
    stored_before_seal = stored()
    vault.sys.seal()
    try:
        require(vault.sys.is_sealed(), 'Vault outage injection did not seal storage')
        ready = requests.get(api + '/api/health/ready', timeout=10)
        require(ready.status_code == 503 and not ready.json()['dependencies']['storage'],
                'Readiness concealed sealed Vault')
        require(requests.get(api + '/api/health/live', timeout=5).ok, 'Storage outage changed API liveness')

        response = requests.put(api + '/api/certificates/' + CERTIFICATE_ID,
                                 json={'domains': [DOMAIN]}, timeout=15)
        require(response.status_code == 503, 'Sealed Vault mutation did not return unavailable')
        for suffix in ('observations', 'metrics'):
            require(requests.get(api + '/api/certificates/' + suffix, timeout=10).status_code == 503,
                    'Sealed Vault supervision returned a successful empty collection')
        cycle('deploy', 'vault-sealed-before-deploy', expect_storage_error=True)
        require(pending.smembers(SERVER_ID) == queued, 'Vault outage lost queue membership')
        require({key: pending.hgetall(key) for key in queued} == pending_before_seal,
                'Vault outage changed pending deployment payloads')
        require(pending.get('cert:' + CERTIFICATE_ID) == issuance_before_seal,
                'Rejected mutation changed pending issuance')
        require(not (directory / 'deployment-starts').exists(),
                'Vault outage unexpectedly submitted an Auton job')
    finally:
        unseal_vault()
    require(stored() == stored_before_seal, 'Vault recovery changed stored certificate')
    phase('sealed-vault-rejects-mutation-and-preserves-pending')
    (directory / 'fail-deployment').touch()
    (directory / 'hold-deployment').touch()
    first_deployer = start(stack, [sys.executable, str(SCRIPT), 'cycle', '--config', config_path,
        '--cycle', 'deploy'], env, directory, 'deployment-failure')
    wait_for(lambda: (directory / 'deployment-held').exists(), 'Held Auton job', [first_deployer])
    cycle('deploy', 'competing-deployer')
    require((directory / 'deployment-starts').read_text().splitlines() == ['started'],
            'Competing deployer submitted a second Auton job')
    require(stored()['status'] == 'generated', 'Competing deployer acknowledged an unfinished job')
    (directory / 'hold-deployment').unlink()
    require(first_deployer.wait(timeout=PHASE_TIMEOUT) == 0, 'First deployer cycle failed')
    phase('concurrent-deployer-does-not-submit-second-job')
    require(stored()['status'] == 'generated' and pending.scard(SERVER_ID) > 0,
            'Failed Auton job falsely acknowledged deployment')
    require(not (directory / 'current').exists(), 'Failed Auton job installed a certificate')
    require((directory / 'injected-failure-executed').exists(),
            'Auton did not actually execute the injected failing job')
    phase('auton-failure-retains-pending')
    # Restart the actual API process while Redis and Vault retain pending work.
    stop(certlord)
    certlord = start(stack, ['certlord', '-f', '-c', config_path,
        '-p', str(directory / 'certlord.pid'), '--logfile', str(directory / 'certlord-daemon.log')],
        env, directory, 'certlord-restarted')
    wait_for(lambda: requests.get(api + '/api/certificates', timeout=1).ok,
             'CertLord restarted', [certlord])
    require(pending.smembers(SERVER_ID) == queued, 'Restart changed pending deployment')
    cycle('crawl', 'queue-after-restart')
    require(pending.smembers(SERVER_ID) == queued, 'Restarted crawler duplicated deployment')
    phase('api-restart-preserves-pending-deployment')
    (directory / 'fail-deployment').unlink()
    from certlord.adapters.deployment_lease import DeploymentLease
    from dwho.adapters.redis import DWhoAdapterRedis
    lease_probe = DeploymentLease(DWhoAdapterRedis(config, prefix='ssl_certs'), SERVER_ID, 1)
    wait_for(lambda: pending.pttl(lease_probe.key) == -2, 'Uncertain deployment lease expiry', timeout=40)
    cycle('deploy', 'deployment-recovery')
    require(stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
            'Successful Auton job did not complete deployment')
    require(all(not pending.exists(key) for key in queued), 'Completed deployment left queue hashes')
    phase('deployment-recovery-cleans-pending-hashes')
    require(stored().get('operation_id') == operation_id, 'Restart/deployment lost operation correlation')
    detail = requests.get(api + '/api/certificates/' + CERTIFICATE_ID, timeout=5).json()
    require(detail.get('operation_id') == operation_id and 'issuance_id' not in detail,
            'Metadata lost operation identity or exposed issuance credential')
    phase('server-operation-id-survives-replay-issuance-restart-and-deployment')
    receipt = stored().get('deployment_receipt')
    require(isinstance(receipt, dict) and set(receipt) == {'origin','endpoint','uid','status','return_code'},
            'Deployment omitted bounded remote receipt metadata')
    require(receipt['origin'] == auton_url and receipt['endpoint'] == 'deploy-fixture'
            and receipt['status'] == 'complete' and receipt['return_code'] == 0,
            'Stored remote receipt does not confirm successful completion')
    endpoint, remote_id = receipt['uid'].split(':', 1)
    remote = requests.get(auton_url + '/status/' + endpoint + '/' + remote_id, timeout=5)
    require(remote.ok and remote.json()['uid'] == receipt['uid']
            and remote.json()['status'] == 'complete' and remote.json()['return_code'] == 0,
            'Stored receipt does not identify the completed remote Auton job')
    phase('stored-auton-receipt-matches-real-completed-remote-job')

    class TLSListener(ThreadingHTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(directory / 'current/fullchain.pem'), str(directory / 'current/key.pem'))
            return context.wrap_socket(connection, server_side=True), address

    listener = TLSListener(('127.0.0.1', 0), Frontend(api).handler())
    http_thread(stack, listener)
    require(served_fingerprint(listener.server_port, trust) == first.fingerprint(hashes.SHA256()).hex(),
            'Served certificate differs from stored issuance')
    phase('auton-deployed-certificate-served-with-trusted-tls')
    cycle('crawl', 'schedule-renewal')
    cycle('issue', 'renewal')
    renewed = certificate_checks(stored())
    require(renewed.serial_number != first.serial_number, 'Renewal reused the certificate')
    require(challenges.dbsize() == 0, 'Renewal left challenge keys')
    cycle('crawl', 'queue-renewal')
    renewal_queue = pending.smembers(SERVER_ID)
    require(len(renewal_queue) == 1, 'Renewal did not queue one deployment')
    renewal_pending = {key: pending.hgetall(key) for key in renewal_queue}
    (directory / 'seal-after-install').touch()
    try:
        cycle('deploy', 'vault-sealed-before-ack', expect_storage_error=True)
        require((directory / 'installed-before-vault-seal').exists() and vault.sys.is_sealed(),
                'Post-install Vault outage was not exercised')
        require(pending.smembers(SERVER_ID) == renewal_queue,
                'Failed Vault acknowledgement removed queue membership')
        require({key: pending.hgetall(key) for key in renewal_queue} == renewal_pending,
                'Failed Vault acknowledgement changed pending payloads')
        require(served_fingerprint(listener.server_port, trust) == renewed.fingerprint(hashes.SHA256()).hex(),
                'Post-install outage did not retain the installed renewed certificate')
    finally:
        (directory / 'seal-after-install').unlink()
        unseal_vault()
    require(stored()['status'] == 'generated', 'Failed Vault acknowledgement falsely marked deployed')
    require(certificate_checks(stored()).serial_number == renewed.serial_number,
            'Post-install outage changed certificate material')
    phase('sealed-vault-after-install-retains-unacknowledged-deployment')
    cycle('deploy', 'deploy-renewal-recovery')
    require(stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
            'Recovered Vault deployment did not complete')
    require(all(not pending.exists(key) for key in renewal_queue),
            'Recovered Vault deployment left pending hashes')
    phase('vault-unsealed-replay-completes-deployment')
    require(served_fingerprint(listener.server_port, trust) == renewed.fingerprint(hashes.SHA256()).hex(),
            'Renewed certificate was not actually served')
    phase('renewed-distinct-certificate-served')
    frontend.reject = True
    before_reads = frontend.reads
    cycle('crawl', 'schedule-invalid-renewal')
    cycle('issue', 'invalid-http01')
    require(frontend.reads > before_reads, 'Negative test did not exercise HTTP-01')
    require(certificate_checks(stored()).serial_number == renewed.serial_number,
            'Rejected HTTP-01 replaced stored certificate')
    state = json.loads(pending.get('cert:' + CERTIFICATE_ID))
    require(state['certs'][DOMAIN]['retry'] > 0, 'Failed issuance did not retain retry state')
    require(challenges.dbsize() == 0, 'Failed validation left challenge keys')
    require(served_fingerprint(listener.server_port, trust) == renewed.fingerprint(hashes.SHA256()).hex(),
            'Failed renewal replaced served certificate')
    phase('invalid-http01-keeps-certificate-and-pending-retry-cleans-challenge')
    # Exercise all three production threads through the real daemon lifecycle.
    frontend.reject = False
    scheduler = copy.deepcopy(config)
    scheduler_port = free_port()
    scheduler_url = 'http://127.0.0.1:%d' % scheduler_port
    scheduler['general']['listen_port'] = scheduler_port
    scheduler_mod = scheduler['modules']['ssl_certs']
    scheduler_mod['routes']['index'].update(at_start=True, at_stop=True)
    scheduler_mod.update(certbot_check_interval=0.2, vault_check_interval=3600,
                         deployer_check_interval=0.2, worker_stop_timeout=5)
    scheduler_path = write_yaml(directory / 'scheduler.yml', scheduler)
    write_yaml(Path(plugin), {'perform': {'uri': scheduler_url}, 'cleanup': {'uri': scheduler_url},
        'deploy': {'uri': scheduler_url, 'path': '/api/ssl-certs/save'}})

    def launch_scheduler(label):
        if args.systemd_scheduler:
            from systemd_process import SystemdProcess
            process = SystemdProcess(scheduler_path, directory, env, report)
            stack.callback(process.cleanup)
            wait_for(lambda: requests.get(scheduler_url + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                     label, [process])
            return process
        process = start(stack, ['certlord', '-f', '-c', scheduler_path,
            '-p', str(directory / 'scheduler.pid'), '--logfile', str(directory / 'scheduler-daemon.log')],
            env, directory, label)
        wait_for(lambda: requests.get(scheduler_url + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                 label, [process])
        return process

    # Real Redis scripts: an old completion cannot overwrite a newer cycle.
    from types import SimpleNamespace
    from certlord.adapters.cycle_progress import CycleProgressStore
    progress_store = CycleProgressStore(SimpleNamespace(servers={'fixture': {'conn': pending}}), SERVER_ID)
    contract_store = CycleProgressStore(SimpleNamespace(servers={'fixture': {'conn': pending}}), 'cycle-contract')
    old_cycle = {'instance_id': str(uuid.uuid4()), 'cycle_id': str(uuid.uuid4()),
                 'state': 'running', 'started_timestamp_seconds': time.time(),
                 'finished_timestamp_seconds': None, 'duration_seconds': None}
    new_cycle = dict(old_cycle, instance_id=str(uuid.uuid4()), cycle_id=str(uuid.uuid4()))
    require(contract_store.start('certlord-deployer', old_cycle), 'Old cycle start not acknowledged')
    require(contract_store.start('certlord-deployer', new_cycle), 'New cycle start not acknowledged')
    require(not contract_store.finish('certlord-deployer', dict(old_cycle, state='returned',
            finished_timestamp_seconds=time.time(), duration_seconds=1)),
            'Late completion overwrote a newer cycle')
    evidence = contract_store.read()['certlord-deployer']
    require(evidence['current'] == new_cycle and evidence['previous_instance'] == old_cycle,
            'Cycle instance boundary lost prior evidence')
    phase('redis-cycle-evidence-preserves-previous-instance-and-rejects-late-finish')

    original_retry = json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]['retry']
    frontend.hold.set()
    try:
        scheduler_process = launch_scheduler('scheduler-issuance')
        wait_for(lambda: requests.get(scheduler_url + '/api/health/ready', timeout=2).status_code == 200,
                 'Running scheduler readiness', [scheduler_process])
        phase('scheduler-ready-with-live-workers-and-reachable-backends')

        wait_for(frontend.held.is_set, 'Scheduler issuance challenge in flight', [scheduler_process])
        cycles = requests.get(scheduler_url + '/api/operations', timeout=10).json()['cycles']
        issuing_cycle = cycles['local']['certlord-certbot_handler']
        require(issuing_cycle['state'] == 'running' and issuing_cycle['persisted'],
                'Held issuance has no persisted running cycle')
        require(cycles['stored']['certlord-certbot_handler']['current']['cycle_id'] == issuing_cycle['cycle_id'],
                'Local and durable issuance cycle IDs differ')
        metric_response = requests.get(scheduler_url + '/api/operations/metrics', timeout=10)
        require(metric_response.ok and 'certlord_worker_cycle_running{worker="certlord-certbot_handler"} 1' in metric_response.text,
                'Running cycle gauge missing')
        require(issuing_cycle['cycle_id'] not in metric_response.text,
                'Metrics expose unbounded cycle ID labels')
        phase('held-scheduler-cycle-visible-in-json-and-bounded-metrics')
        interrupted_challenges = set(challenges.scan_iter())
        require(interrupted_challenges and all(0 < challenges.ttl(key) <= 30 for key in interrupted_challenges),
                'In-flight challenges have no bounded lifetime')
        graceful_stop(scheduler_process, 'Scheduler interrupted during issuance')
        stopped_cycle = progress_store.read()['certlord-certbot_handler']['current']
        require(stopped_cycle['cycle_id'] == issuing_cycle['cycle_id'] and stopped_cycle['state'] == 'stopped',
                'Graceful interruption did not persist the stopped cycle')
        phase('graceful-stop-persists-cycle-outcome-without-success-claim')
        report['interrupted_challenges_after_stop'] = sum(challenges.exists(key) for key in interrupted_challenges)
        state = json.loads(pending.get('cert:' + CERTIFICATE_ID))
        require(state['certs'][DOMAIN]['retry'] == original_retry,
                'Interrupted scheduler issuance consumed a retry or lost pending work')
        require(certificate_checks(stored()).serial_number == renewed.serial_number,
                'Interrupted issuance replaced stored certificate')
        require(served_fingerprint(listener.server_port, trust) == renewed.fingerprint(hashes.SHA256()).hex(),
                'Interrupted issuance replaced served certificate')
    finally:
        frontend.hold.clear()
    phase('full-scheduler-graceful-stop-preserves-in-flight-issuance')
    wait_for(lambda: all(not challenges.exists(key) for key in interrupted_challenges),
             'Interrupted challenge cleanup or expiry', timeout=35)
    require(challenges.dbsize() == 0, 'Interrupted issuance left unrelated challenge keys')
    phase('interrupted-issuance-challenges-have-bounded-redis-lifetime')
    # A fresh scheduler must resume issuance and reach the real Auton job.
    (directory / 'deployment-held').unlink(missing_ok=True)
    (directory / 'injected-failure-executed').unlink(missing_ok=True)
    (directory / 'hold-deployment').touch()
    (directory / 'fail-deployment').touch()
    try:
        scheduler_process = launch_scheduler('scheduler-deployment')
        def resumed_deployment():
            current = stored()
            pending_value = pending.get('cert:' + CERTIFICATE_ID)
            pending_state = json.loads(pending_value)['certs'].get(DOMAIN, {}) if pending_value else {}
            report['scheduler_checkpoint'] = {
                'stored_status': current.get('status'),
                'certificate_changed': certificate_checks(current).serial_number != renewed.serial_number,
                'pending_status': pending_state.get('status'), 'retry': pending_state.get('retry'),
                'queue_size': pending.scard(SERVER_ID)}
            return (directory / 'deployment-held').exists()
        wait_for(resumed_deployment, 'Resumed scheduler reached Auton deployment',
                 [scheduler_process], timeout=60)
        scheduler_certificate = certificate_checks(stored())
        require(scheduler_certificate.serial_number != renewed.serial_number,
                'Scheduler restart did not resume issuance')
        scheduler_queue = pending.smembers(SERVER_ID)
        require(scheduler_queue, 'Scheduler deployment has no pending operation')
        graceful_stop(scheduler_process, 'Scheduler interrupted during deployment')
        require(stored()['status'] == 'generated' and pending.smembers(SERVER_ID) == scheduler_queue,
                'Interrupted scheduler falsely acknowledged deployment')
        require(served_fingerprint(listener.server_port, trust) == renewed.fingerprint(hashes.SHA256()).hex(),
                'Held deployment replaced served certificate')
    finally:
        (directory / 'hold-deployment').unlink(missing_ok=True)
    wait_for(lambda: (directory / 'injected-failure-executed').exists(), 'Surviving fixture job failure')
    (directory / 'fail-deployment').unlink()
    phase('full-scheduler-stop-preserves-unfinished-remote-deployment')
    wait_for(lambda: pending.pttl(lease_probe.key) == -2, 'Interrupted scheduler lease expiry', timeout=40)
    scheduler_process = launch_scheduler('scheduler-recovery')
    wait_for(lambda: stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
             'Full scheduler recovery', [scheduler_process], timeout=60)
    require(all(not pending.exists(key) for key in scheduler_queue), 'Scheduler recovery left pending hashes')
    require(served_fingerprint(listener.server_port, trust) == scheduler_certificate.fingerprint(hashes.SHA256()).hex(),
            'Scheduler recovery did not serve its issued certificate')
    graceful_stop(scheduler_process, 'Recovered scheduler')
    phase('full-scheduler-restart-recovers-through-verified-tls')
    if args.systemd_scheduler:
        report['status'] = 'passed'
        return
    # Create a distinct renewal while the scheduler is stopped, then crash its
    # actual daemon while a remote deployment is in flight. Redis/Vault survive.
    write_yaml(Path(plugin), {'perform': {'uri': api}, 'cleanup': {'uri': api},
        'deploy': {'uri': api, 'path': '/api/ssl-certs/save'}})
    cycle('crawl', 'schedule-crash-renewal')
    cycle('issue', 'issue-crash-renewal')
    crash_certificate = certificate_checks(stored())
    require(crash_certificate.serial_number != scheduler_certificate.serial_number,
            'Crash fixture did not issue a distinct renewal')
    (directory / 'deployment-held').unlink(missing_ok=True)
    (directory / 'injected-failure-executed').unlink(missing_ok=True)
    (directory / 'hold-deployment').touch()
    (directory / 'fail-deployment').touch()
    try:
        scheduler_process = launch_scheduler('scheduler-before-sigkill')
        wait_for(lambda: (directory / 'deployment-held').exists(),
                 'Deployment in flight before SIGKILL', [scheduler_process], timeout=30)
        crash_queue = pending.smembers(SERVER_ID)
        require(len(crash_queue) == 1, 'Crash fixture has unexpected queue membership')
        crash_payloads = {key: pending.hgetall(key) for key in crash_queue}
        job_count = len((directory / 'deployment-starts').read_text().splitlines())
        killed_cycle = progress_store.read()['certlord-deployer']['current']
        require(killed_cycle['state'] == 'running', 'In-flight deployment has no running evidence')
        # Kill only this fixture daemon. No runtime stop hook is executed.
        children = psutil.Process(scheduler_process.pid).children(recursive=True)
        scheduler_process.kill()
        require(scheduler_process.wait(timeout=5) == -signal.SIGKILL,
                'Fixture daemon did not die by SIGKILL')
        # Explicit harness cleanup emulates service-manager cleanup of local
        # descendants. It is not a claim that a killed parent reaps its children.
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(children, timeout=3)
        require(all(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE for child in children),
                'Local crash fixture child survived cleanup')
        require(stored()['status'] == 'generated' and pending.smembers(SERVER_ID) == crash_queue,
                'SIGKILL lost pending work or falsely acknowledged deployment')
        require({key: pending.hgetall(key) for key in crash_queue} == crash_payloads,
                'SIGKILL changed queued deployment data')
        require(pending.pttl(lease_probe.key) > 0, 'Crash unexpectedly released the deployment lease')
        require(served_fingerprint(listener.server_port, trust) == scheduler_certificate.fingerprint(hashes.SHA256()).hex(),
                'Crash replaced the previous served certificate')
        # Restart with the stale PID file and unexpired lease still in place.
        scheduler_process = launch_scheduler('scheduler-after-sigkill')
        time.sleep(1)
        require(len((directory / 'deployment-starts').read_text().splitlines()) == job_count,
                'Restart submitted a duplicate job before the old lease expired')
        require(pending.pttl(lease_probe.key) > 0, 'Lease expired before restart exclusion was checked')
        recovered_cycles = progress_store.read()['certlord-deployer']
        require(recovered_cycles['previous_instance'] == killed_cycle,
                'Restart lost the unfinished previous-instance cycle')
        require(recovered_cycles['current']['instance_id'] != killed_cycle['instance_id'],
                'Restart reused the previous instance ID')
        phase('sigkill-cycle-evidence-survives-restart-without-invented-completion')
        phase('sigkill-preserves-pending-and-restart-respects-existing-lease')
    finally:
        (directory / 'hold-deployment').unlink(missing_ok=True)
    wait_for(lambda: (directory / 'injected-failure-executed').exists(),
             'Remote job survived local SIGKILL and failed')
    (directory / 'fail-deployment').unlink()
    wait_for(lambda: stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
             'Scheduler SIGKILL recovery after lease expiry', [scheduler_process], timeout=60)
    require(all(not pending.exists(key) for key in crash_queue), 'SIGKILL recovery left queue hashes')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'SIGKILL recovery did not serve the renewed certificate')
    graceful_stop(scheduler_process, 'Scheduler recovered after SIGKILL')
    phase('sigkill-recovery-replays-pending-through-verified-tls')
    fault = VaultFaultProxy(vault_url)
    fault_server = ThreadingHTTPServer(('127.0.0.1', 0), fault.handler())
    http_thread(stack, fault_server)
    stack.callback(fault.release.set)
    fault_config = copy.deepcopy(scheduler)
    fault_port = free_port()
    fault_api = 'http://127.0.0.1:%d' % fault_port
    fault_config['general']['listen_port'] = fault_port
    fault_creds = yaml.safe_load(Path(creds).read_text())
    fault_creds['vault']['uri'] = 'http://127.0.0.1:%d' % fault_server.server_port
    fault_config['credentials'] = write_yaml(directory / 'fault-credentials.yml', fault_creds)
    fault_mod = fault_config['modules']['ssl_certs']
    fault_mod.update(vault_check_interval=0.2, renew_before_expiry=1)
    fault_mod['routes']['index'].update(at_start=False, at_stop=False)
    fault_path = write_yaml(directory / 'fault-api.yml', fault_config)

    def launch_fault(label):
        process = start(stack, ['certlord', '-f', '-c', fault_path,
            '-p', str(directory / 'fault-api.pid'), '--logfile', str(directory / 'fault-daemon.log')],
            env, directory, label)
        wait_for(lambda: requests.get(fault_api + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                 label, [process])
        return process

    fault_process = launch_fault('vault-fault-api')
    # Seed one legitimate redeployment; mutation failure must not consume it.
    vault.secrets.kv.v2.patch(SECRET_PATH, secret={'status': 'generated'})
    cycle('crawl', 'queue-network-fault')
    fault_queue = pending.smembers(SERVER_ID)
    require(len(fault_queue) == 1, 'Network fault fixture has no pending deployment')
    fault_payloads = {key: pending.hgetall(key) for key in fault_queue}
    before_fault = stored()
    fault.blocked.set()
    try:
        started = time.monotonic()
        response = requests.put(fault_api + '/api/certificates/' + CERTIFICATE_ID,
                                 json={'domains': [DOMAIN]}, timeout=15)
        elapsed = time.monotonic() - started
        require(fault.observed.is_set(), 'Vault blackhole was not exercised')
        require(response.status_code == 503 and 8 <= elapsed < 15,
                'Nonresponding Vault did not produce bounded HTTP 503')
        require(stored() == before_fault and pending.smembers(SERVER_ID) == fault_queue,
                'Nonresponding Vault lost work or changed stored state')
        require({key: pending.hgetall(key) for key in fault_queue} == fault_payloads,
                'Nonresponding Vault changed deployment payloads')
        require(token not in response.text and before_fault['key'] not in response.text,
                'Vault timeout response exposed credentials or key material')
        report['vault_timeout_seconds'] = round(elapsed, 2)
    finally:
        fault.blocked.clear()
        fault.release.set()
    graceful_stop(fault_process, 'API after Vault timeout')
    phase('nonresponding-vault-times-out-without-losing-pending-work')
    fault_mod['routes']['index'].update(at_start=True, at_stop=True)
    write_yaml(Path(fault_path), fault_config)
    fault_process = launch_fault('scheduler-after-vault-timeout')
    wait_for(lambda: stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
             'Recovery after Vault network timeout', [fault_process], timeout=30)
    require(all(not pending.exists(key) for key in fault_queue), 'Timeout recovery left queue hashes')
    fault.release.clear()
    fault.observed.clear()
    fault.blocked.set()
    try:
        wait_for(fault.observed.is_set, 'Scheduler blocked on silent Vault', [fault_process])
        graceful_stop(fault_process, 'Scheduler stopped during silent Vault I/O')
        require('Workers still stopping:' in (directory / 'fault-daemon.log').read_text(),
                'Blocked worker was not reported at the join deadline')
    finally:
        fault.blocked.clear()
        fault.release.set()
    phase('scheduler-stop-bounds-join-and-reports-blocked-vault-worker')
    fault_process = launch_fault('scheduler-after-blocked-stop')
    require(stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
            'Restart after blocked stop changed completed deployment')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Network fault or restart changed served certificate')
    graceful_stop(fault_process, 'Recovered scheduler after blocked I/O')
    phase('silent-vault-recovery-and-restart-preserve-served-tls')
    # Real Redis socket stall after successful daemon startup. The direct fixture
    # connection seeds work behind the blocked proxy; production clients cannot see
    # or acknowledge it until a fresh daemon starts after fault recovery.
    from network_faults import RedisFaultProxy, DnsFaultServer
    redis_fault = RedisFaultProxy(redis_port)
    redis_fault_server = redis_fault.server()
    http_thread(stack, redis_fault_server)
    stack.callback(redis_fault.release.set)
    redis_scheduler = copy.deepcopy(scheduler)
    redis_api = 'http://127.0.0.1:%d' % free_port()
    redis_scheduler['general']['listen_port'] = int(redis_api.rsplit(':', 1)[1])
    redis_scheduler['general']['redis'] = {
        name: {'url': 'redis://127.0.0.1:%d?db=%d&socket_timeout=2&socket_connect_timeout=2' %
               (redis_fault_server.server_address[1], db)}
        for name, db in (('ssl_certs', 1), ('letsencrypt', 0))}
    redis_scheduler['modules']['ssl_certs'].update(renew_before_expiry=1, worker_stop_timeout=5)
    redis_scheduler_path = write_yaml(directory / 'redis-scheduler.yml', redis_scheduler)
    redis_log = directory / 'redis-scheduler-daemon.log'

    def launch_redis_scheduler(label):
        process = start(stack, ['certlord', '-f', '-c', redis_scheduler_path,
            '-p', str(directory / 'redis-scheduler.pid'), '--logfile', str(redis_log)],
            env, directory, label)
        wait_for(lambda: requests.get(redis_api + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                 label, [process])
        return process

    redis_scheduler_process = launch_redis_scheduler('redis-stall-scheduler')
    redis_fault.blocked.set()
    wait_for(redis_fault.observed.is_set, 'Scheduler request blocked on Redis', [redis_scheduler_process])
    vault.secrets.kv.v2.patch(SECRET_PATH, secret={'status': 'generated'})
    cycle('crawl', 'queue-while-scheduler-redis-blocked')
    stalled_queue = pending.smembers(SERVER_ID)
    require(len(stalled_queue) == 1, 'Redis stall fixture did not queue one deployment')
    stalled_payloads = {key: pending.hgetall(key) for key in stalled_queue}
    stalled_record = stored()
    starts_before = len((directory / 'deployment-starts').read_text().splitlines())
    started = time.monotonic()
    try:
        graceful_stop(redis_scheduler_process, 'Scheduler stop during blocked Redis', timeout=8)
        report['redis_stalled_stop_seconds'] = round(time.monotonic() - started, 2)
        require('Workers still stopping:' not in redis_log.read_text(),
                'Redis worker exceeded the configured join budget')
        require(pending.smembers(SERVER_ID) == stalled_queue and
                {key: pending.hgetall(key) for key in stalled_queue} == stalled_payloads,
                'Blocked Redis shutdown consumed or changed pending deployment')
        require(stored() == stalled_record, 'Blocked Redis shutdown changed certificate storage')
        require(len((directory / 'deployment-starts').read_text().splitlines()) == starts_before,
                'Blocked Redis submitted an unexpected remote deployment')
        require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
                'Blocked Redis changed the served certificate')
    finally:
        redis_fault.blocked.clear()
        redis_fault.release.set()
    phase('scheduler-redis-stall-stops-within-budget-and-preserves-pending-work')
    redis_scheduler_process = launch_redis_scheduler('redis-stall-recovery')
    wait_for(lambda: stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
             'Redis stall recovery deployment', [redis_scheduler_process], timeout=40)
    require(all(not pending.exists(key) for key in stalled_queue), 'Redis recovery left pending hashes')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Redis recovery did not serve the expected certificate')
    graceful_stop(redis_scheduler_process, 'Redis recovery scheduler')
    phase('scheduler-redis-stall-restart-recovers-deployment-through-served-tls')

    # A real UDP DNS query during renewal. Inject only the fixture nameserver
    # destination; do not replace resolver results or scheduler/application code.
    dns_fault = DnsFaultServer()
    dns_fault_server = dns_fault.server()
    http_thread(stack, dns_fault_server)
    dns_fault.blocked.set()
    dns_scheduler = copy.deepcopy(scheduler)
    dns_api = 'http://127.0.0.1:%d' % free_port()
    dns_scheduler['general']['listen_port'] = int(dns_api.rsplit(':', 1)[1])
    # Renew the aged fixture certificate once; a threshold of 365 days also
    # makes every fresh Pebble certificate immediately eligible again.
    dns_renew_window = (crash_certificate.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / 86400 + 2 / 86400
    dns_scheduler['modules']['ssl_certs'].update(
        allow_dns_resolv={'a': [r'^127\.0\.0\.1$']}, expected_caa_records=[],
        dns_timeout=2, worker_stop_timeout=5, renew_before_expiry=dns_renew_window)
    dns_scheduler_path = write_yaml(directory / 'dns-scheduler.yml', dns_scheduler)
    dns_log = directory / 'dns-scheduler-daemon.log'
    from certlord.classes.ssl_cert_auto_object import SslCertAutoObject
    dns_pending = SslCertAutoObject(CERTIFICATE_ID)
    dns_pending.add_dom(DOMAIN, 'invalid-dns')
    pending.set('cert:' + CERTIFICATE_ID, dns_pending.dumps())
    before_dns = stored()
    plugin_before_dns = Path(plugin).read_text()
    write_yaml(Path(plugin), {'perform': {'uri': dns_api}, 'cleanup': {'uri': dns_api},
                             'deploy': {'uri': dns_api, 'path': '/api/ssl-certs/save'}})

    def launch_dns_scheduler(label):
        process = start(stack, [sys.executable, str(SCRIPT), 'dns-daemon',
            '--config', dns_scheduler_path, '--dns-port', str(dns_fault_server.server_address[1]),
            '--pidfile', str(directory / 'dns-scheduler.pid'), '--logfile', str(dns_log)],
            env, directory, label)
        wait_for(lambda: requests.get(dns_api + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                 label, [process])
        return process

    try:
        dns_scheduler_process = launch_dns_scheduler('dns-stall-scheduler')
        wait_for(dns_fault.observed.is_set, 'Scheduler DNS query reached silent listener', [dns_scheduler_process])
        started = time.monotonic()
        graceful_stop(dns_scheduler_process, 'Scheduler stop during blocked DNS', timeout=8)
        report['dns_stalled_stop_seconds'] = round(time.monotonic() - started, 2)
        require('Workers still stopping:' not in dns_log.read_text(),
                'DNS worker exceeded the configured join budget')
        after_dns = stored()
        require(all(after_dns[field] == before_dns[field] for field in ('cert', 'key', 'chain')),
                'Silent DNS changed certificate material')
        dns_state = json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]
        require(dns_state['retry'] == 0 and dns_state['status'] == 'invalid-dns',
                'Silent DNS lost pending renewal or consumed an issuance retry')
        require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
                'Silent DNS changed served TLS')
        phase('scheduler-dns-stall-stops-within-budget-and-preserves-renewal')
        dns_fault.blocked.clear()
        dns_scheduler_process = launch_dns_scheduler('dns-stall-recovery')
        previous_serial = crash_certificate.serial_number
        def dns_renewed():
            current = stored()
            pending_value = pending.get('cert:' + CERTIFICATE_ID)
            pending_state = json.loads(pending_value)['certs'].get(DOMAIN, {}) if pending_value else {}
            children = psutil.Process(dns_scheduler_process.pid).children(recursive=True)
            challenge_keys = list(challenges.scan_iter())
            report['dns_recovery_checkpoint'] = {
                'stored_status': current.get('status'),
                'certificate_changed': certificate_checks(current).serial_number != previous_serial,
                'pending_status': pending_state.get('status'), 'retry': pending_state.get('retry'),
                'queue_size': pending.scard(SERVER_ID),
                'challenge_database_keys': len(challenge_keys),
                'http_challenge_keys': sum(b'/.well-known/acme-challenge/' in key for key in challenge_keys),
                'child_count': len(children)}
            if report['dns_recovery_checkpoint']['certificate_changed'] and not children:
                require(not challenge_keys, 'Completed DNS renewal left challenge data')
            return (current.get('status') == 'deployed' and pending.scard(SERVER_ID) == 0
                    and certificate_checks(current).serial_number != previous_serial
                    and challenges.dbsize() == 0
                    and not children)
        wait_for(dns_renewed, 'DNS recovery renewal and deployment', [dns_scheduler_process], timeout=60)
        crash_certificate = certificate_checks(stored())
        require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
                'DNS recovery did not serve the renewed certificate')
        require(crash_certificate.not_valid_after_utc - timedelta(days=dns_renew_window) > datetime.now(timezone.utc),
                'Recovered certificate is already eligible for another fixture renewal')
        graceful_stop(dns_scheduler_process, 'DNS recovery scheduler')
        require(challenges.dbsize() == 0, 'DNS recovery left challenge data after command completion')
        phase('scheduler-dns-stall-restart-renews-and-serves-distinct-certificate')
    finally:
        dns_fault.blocked.clear()
        Path(plugin).write_text(plugin_before_dns)

    # Exercise the real optional monitoring adapter/SDK over loopback HTTP. The
    # provider is disposable; no external account or production key is involved.
    from network_faults import MonitoringFaultServer
    monitor_fault = MonitoringFaultServer()
    monitor_server = monitor_fault.server()
    http_thread(stack, monitor_server)
    stack.callback(monitor_fault.release.set)
    monitor_fault.blocked.set()
    monitor_config = copy.deepcopy(scheduler)
    monitor_api = 'http://127.0.0.1:%d' % free_port()
    monitor_config['general']['listen_port'] = int(monitor_api.rsplit(':', 1)[1])
    monitor_config['modules']['ssl_certs'].update(renew_before_expiry=1, vault_check_interval=0.5)
    monitor_config['ssl_checkers'] = {'updown': {
        'enabled': True, 'timeout': 2, 'recipients': ['email:123']}}
    monitor_credentials = yaml.safe_load(Path(creds).read_text())
    monitor_credentials['updown'] = {'api-key': 'disposable-fixture-key'}
    monitor_config['credentials'] = write_yaml(directory / 'monitoring-credentials.yml', monitor_credentials)
    monitor_path = write_yaml(directory / 'monitoring-scheduler.yml', monitor_config)
    monitor_env = dict(env, UPDOWN_ENDPOINT='http://127.0.0.1:%d' % monitor_server.server_port)
    monitor_log = directory / 'monitoring-daemon.log'

    def launch_monitor(label):
        process = start(stack, ['certlord', '-f', '-c', monitor_path,
            '-p', str(directory / 'monitoring.pid'), '--logfile', str(monitor_log)],
            monitor_env, directory, label)
        wait_for(lambda: requests.get(monitor_api + '/api/certificates/' + CERTIFICATE_ID, timeout=1).ok,
                 label, [process])
        return process

    monitor_before = stored()
    monitor_process = launch_monitor('monitoring-stall')
    wait_for(monitor_fault.observed.is_set, 'Monitoring listing reached silent provider', [monitor_process])
    started = time.monotonic()
    graceful_stop(monitor_process, 'Scheduler stop during blocked monitoring', timeout=8)
    report['monitoring_stalled_stop_seconds'] = round(time.monotonic() - started, 2)
    require('Workers still stopping:' not in monitor_log.read_text(),
            'Monitoring worker exceeded the configured join budget')
    require(stored() == monitor_before and pending.scard(SERVER_ID) == 0,
            'Monitoring stall changed certificate or deployment state')
    require(monitor_fault.snapshot()['creates'] == 0, 'Failed discovery allowed monitoring creation')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Monitoring stall changed served TLS')
    phase('scheduler-monitoring-stall-stops-within-budget-and-preserves-certificate')
    monitor_fault.blocked.clear()
    monitor_fault.release.set()
    monitor_fault.drop_create_reply.set()
    monitor_process = launch_monitor('monitoring-recovery')
    wait_for(lambda: monitor_fault.snapshot()['creates'] >= 1, 'Monitoring creation with lost response',
             [monitor_process], timeout=20)
    listed_before = monitor_fault.snapshot()['listings']
    wait_for(lambda: monitor_fault.snapshot()['listings'] >= listed_before + 3,
             'Monitoring rediscovery after uncertain creation', [monitor_process], timeout=20)
    graceful_stop(monitor_process, 'Monitoring recovery scheduler')
    require(monitor_fault.snapshot()['creates'] == 1 and monitor_fault.snapshot()['controls'] == 1,
            'Monitoring recovery duplicated an already applied creation')
    monitor_process = launch_monitor('monitoring-second-restart')
    listed_before = monitor_fault.snapshot()['listings']
    wait_for(lambda: monitor_fault.snapshot()['listings'] >= listed_before + 3,
             'Fresh daemon monitoring rediscovery', [monitor_process], timeout=20)
    graceful_stop(monitor_process, 'Monitoring rediscovery scheduler')
    require(monitor_fault.snapshot()['creates'] == 1 and stored() == monitor_before,
            'Fresh monitoring daemon duplicated control or changed certificate')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Monitoring recovery changed served TLS')
    report['monitoring_recovery_checkpoint'] = monitor_fault.snapshot()
    phase('scheduler-monitoring-lost-create-response-recovers-without-duplicate-after-restart')

    # Share the same certificate across two certificate_ids, then remove one while the
    # actual Auton job is held. A remote effect may finish; its old CAS must not.
    shared_certificate_id = '111f28d0-6329-5015-9a14-8532c1f6f533'
    shared_path = 'certlord-fixture/' + shared_certificate_id + '/' + DOMAIN
    # Seed an existing shared record directly as a pre-index fixture. HTTP PUT
    # may update/restore known identities, but cannot allocate client-chosen UUIDs.
    shared_seed = dict(stored(), status='generated')
    shared_seed.pop('issuance_id', None)
    shared_seed.pop('issuance_complete', None)
    vault.secrets.kv.v2.create_or_update_secret(shared_path, secret=shared_seed)
    require(requests.put(api + '/api/certificates/' + shared_certificate_id,
                          json={'domains': [DOMAIN]}, timeout=10).ok, 'Shared-certificate_id creation rejected')
    shared_data = vault.secrets.kv.v2.read_secret_version(shared_path)['data']['data']
    require(certificate_checks(shared_data).serial_number == crash_certificate.serial_number,
            'Shared certificate_id did not reuse the existing certificate')
    vault.secrets.kv.v2.patch(SECRET_PATH, secret={'status': 'generated'})
    cycle('crawl', 'queue-shared-deployment')
    shared_queue = pending.smembers(SERVER_ID)
    require(len(shared_queue) == 2, 'Shared certificate did not queue both certificate_id records')
    ambiguous = client_command('remove', DOMAIN)
    require(ambiguous.returncode != 0 and 'Ambiguous' in ambiguous.stderr,
            'Ambiguous CLI domain selected a certificate automatically')
    require(requests.get(api + '/api/certificates/' + CERTIFICATE_ID, timeout=5).json()['certificate_id'] == CERTIFICATE_ID,
            'Renewal changed the managed certificate UUID')
    phase('stable-uuid-through-renewal-and-ambiguous-domain-refusal')

    (directory / 'deployment-held').unlink(missing_ok=True)
    (directory / 'hold-deployment').touch()
    try:
        in_flight = start(stack, [sys.executable, str(SCRIPT), 'cycle', '--config', config_path,
            '--cycle', 'deploy'], env, directory, 'remove-during-deployment')
        wait_for(lambda: (directory / 'deployment-held').exists(),
                 'Shared Auton deployment in flight', [in_flight])
        require(requests.delete(api + '/api/certificates/' + CERTIFICATE_ID,
                              json={'domains': []}, timeout=10).ok,
                'In-flight removal request rejected')
        require(stored()['status'] == 'delete', 'Removal did not invalidate the deployed snapshot')
    finally:
        (directory / 'hold-deployment').unlink(missing_ok=True)
    require(in_flight.wait(timeout=PHASE_TIMEOUT) == 0, 'In-flight deployer did not complete its cycle')
    require(stored()['status'] == 'delete', 'Late Auton success overwrote deletion intent')
    require(json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]['status'] == 'delete',
            'In-flight deployment consumed the deletion request')
    require(pending.scard(SERVER_ID) == 1, 'Conflicting deployment was falsely acknowledged')
    phase('removal-during-auton-job-rejects-stale-deployment-acknowledgement')
    cycle('issue', 'remove-first-shared-certificate_id')
    cycle('deploy', 'cleanup-deleted-certificate_id-deployment')
    require_destroyed_certificate(vault, SECRET_PATH)
    retained = vault.secrets.kv.v2.read_secret_version(shared_path)['data']['data']
    require(certificate_checks(retained).serial_number == crash_certificate.serial_number,
            'Removing first certificate_id changed the remaining certificate_id certificate')
    require(retained['status'] == 'deployed', 'Remaining shared-certificate_id deployment did not complete')
    require(json.loads(pending.get('domain:' + DOMAIN))['certificate_ids'] == [shared_certificate_id],
            'Shared reverse association was lost or resurrected')
    require(pending.scard(SERVER_ID) == 0 and all(not pending.exists(k) for k in shared_queue),
            'Deleted certificate blocked obsolete deployment cleanup')
    phase('shared-certificate_id-removal-preserves-other-certificate-and-cleans-obsolete-queue')
    # Restore the primary certificate_id from the remaining copy, then remove the secondary.
    require(requests.put(api + '/api/certificates/' + CERTIFICATE_ID,
                          json={'domains': [DOMAIN]}, timeout=10).ok, 'Primary shared-certificate_id restore failed')
    require(requests.delete(api + '/api/certificates/' + shared_certificate_id,
                          json={'domains': []}, timeout=10).ok, 'Secondary shared-certificate_id removal failed')
    cycle('issue', 'remove-secondary-shared-certificate_id')
    cycle('crawl', 'queue-restored-primary-certificate_id')
    cycle('deploy', 'deploy-restored-primary-certificate_id')
    require(stored()['status'] == 'deployed' and pending.scard(SERVER_ID) == 0,
            'Restored shared certificate did not complete deployment')
    require(json.loads(pending.get('domain:' + DOMAIN))['certificate_ids'] == [CERTIFICATE_ID],
            'Restored shared association is incorrect')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Shared-certificate_id changes replaced the expected served certificate')
    phase('shared-certificate-restoration-reuses-material-and-deploys')
    save_coordination_checks(vault, config, stored(), phase)
    # Deletion is managed-store removal, not certificate revocation or remote uninstall.
    response = requests.delete(api + '/api/certificates/' + CERTIFICATE_ID,
                             json={'domains': []}, timeout=10)
    require(response.ok, 'Certificate removal request rejected')
    before_removal = stored()
    require(before_removal['status'] == 'delete', 'Deletion was not recorded in Vault')
    removal_state = json.loads(pending.get('cert:' + CERTIFICATE_ID))
    require(removal_state['certs'][DOMAIN]['status'] == 'delete', 'Removal was not queued')
    require(CERTIFICATE_ID not in json.loads(pending.get('domain:' + DOMAIN))['certificate_ids'],
            'Removal retained the reverse certificate_id association')
    cycle('crawl', 'crawl-before-removal')
    require(json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]['status'] == 'delete',
            'Crawler overwrote the requested deletion')
    require(CERTIFICATE_ID not in json.loads(pending.get('domain:' + DOMAIN))['certificate_ids'],
            'Crawler restored a removed certificate_id association')
    phase('crawler-preserves-requested-removal')
    # Real Vault policy denial at deletion, while authentication/read/list work.
    policy = '''path "auth/token/lookup-self" { capabilities = ["read"] }
path "secret/data/certlord-fixture/*" { capabilities = ["read"] }
path "secret/metadata/certlord-fixture" { capabilities = ["list"] }
path "secret/metadata/certlord-fixture/*" { capabilities = ["list"] }
'''
    vault.sys.create_or_update_policy('deletion-denied-fixture', policy)
    limited_token = vault.auth.token.create(policies=['deletion-denied-fixture'],
                                          no_default_policy=True, ttl='60s')['auth']['client_token']
    denied_config = copy.deepcopy(config)
    denied_creds = yaml.safe_load(Path(creds).read_text())
    denied_creds['vault']['token'] = limited_token
    denied_config['credentials'] = write_yaml(directory / 'delete-denied-credentials.yml', denied_creds)
    denied_path = write_yaml(directory / 'delete-denied.yml', denied_config)
    previous_retry = json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]['retry']
    run([sys.executable, str(SCRIPT), 'cycle', '--config', denied_path, '--cycle', 'issue'],
        env, directory, 'delete-denied')
    failed_removal = json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'][DOMAIN]
    require(failed_removal['status'] == 'delete' and failed_removal['retry'] == previous_retry + 1,
            'Denied deletion lost pending intent or did not retain retry state')
    require(stored() == before_removal, 'Denied deletion changed Vault certificate material')
    vault.auth.token.revoke(limited_token)
    phase('vault-denied-removal-retains-certificate-and-retry')
    cycle('issue', 'delete-recovered')
    require_destroyed_certificate(vault, SECRET_PATH)
    require(DOMAIN not in json.loads(pending.get('cert:' + CERTIFICATE_ID))['certs'],
            'Completed deletion retained pending operation')
    cycle('issue', 'cleanup-empty-removal-state')
    require(not pending.exists('cert:' + CERTIFICATE_ID), 'Completed deletion retained empty pending-state key')
    require(json.loads(pending.get('domain:' + DOMAIN))['certificate_ids'] == [],
            'Completed deletion retained reverse associations')
    require(pending.scard(SERVER_ID) == 0, 'Removal queued an unexpected deployment')
    require(requests.get(api + '/api/certificates/' + CERTIFICATE_ID, timeout=5).status_code == 404,
            'Removed certificate remains in API inventory')
    require(requests.delete(api + '/api/certificates/' + CERTIFICATE_ID,
                          json={'domains': []}, timeout=10).ok,
            'Repeated removal was not accepted')
    cycle('issue', 'repeated-removal-cleanup')
    require(not pending.exists('cert:' + CERTIFICATE_ID), 'Repeated removal left pending work')
    require(served_fingerprint(listener.server_port, trust) == crash_certificate.fingerprint(hashes.SHA256()).hex(),
            'Managed-store deletion unexpectedly uninstalled the served certificate')
    phase('removal-recovery-cleans-vault-and-pending-state-idempotently')
    # External acquisition uses the same storage/queue/deployment adapters, no ACME request.
    external_domain = 'imported.example.test'
    issuer = x509.load_pem_x509_certificate(tls_cert.read_bytes())
    issuer_key = serialization.load_pem_private_key(tls_key.read_bytes(), password=None)
    external_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    external_cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, external_domain)]))
        .issuer_name(issuer.subject).public_key(external_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(external_domain)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256()))
    external_payload = {'domain': external_domain,
        'cert': external_cert.public_bytes(serialization.Encoding.PEM).decode(),
        'chain': tls_cert.read_text(),
        'key': external_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()).decode()}
    response = requests.post(api + '/api/certificates/import', json=external_payload, timeout=10)
    require(response.ok, 'External import failed')
    imported = response.json()
    imported_id = imported['certificate_id']
    import_operation_id = imported.get('operation_id')
    require(uuid.UUID(import_operation_id).version == 4, 'Import omitted operation identity')
    uuid.UUID(imported_id)
    require(imported.get('origin') == 'external' and imported.get('renewal_owner') == 'external',
            'External import ownership missing')
    require(not any(key in imported for key in ('cert', 'key', 'chain')), 'Import exposed private material')
    imported_path = 'certlord-fixture/' + imported_id + '/' + external_domain
    initial_import = vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']
    require(initial_import['data']['key'] == external_payload['key'], 'Vault import did not retain private material')
    # Installed CLI sends file contents over HTTP and outputs metadata only.
    external_files = {}
    for field in ('cert', 'key', 'chain'):
        path = directory / ('external-' + field + '.pem')
        path.write_text(external_payload[field])
        path.chmod(0o600)
        external_files[field] = str(path)
    replay = subprocess.run(['certlord', 'import', external_domain, '--url', api, '--json',
        '--cert-file', external_files['cert'], '--key-file', external_files['key'],
        '--chain-file', external_files['chain']], env=env, capture_output=True, timeout=15)
    require(replay.returncode == 0 and json.loads(replay.stdout)['certificate_id'] == imported_id,
            'Installed import CLI did not reuse server identity')
    require(vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['metadata']['version']
            == initial_import['metadata']['version'], 'Identical import rewrote Vault material')
    require(requests.post(api + '/api/certificates/import', json=dict(external_payload, chain=''), timeout=10).status_code == 409,
            'Valid but different material implicitly replaced existing import')
    require(vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['metadata']['version']
            == initial_import['metadata']['version'], 'Rejected replacement changed Vault version')
    changed = dict(external_payload, key=tls_key.read_text())
    require(requests.post(api + '/api/certificates/import', json=changed, timeout=10).status_code == 400,
            'Mismatched import key accepted')
    phase('external-import-api-cli-vault-identity-replay-and-private-output')
    response = requests.get(api + '/api/certificates/observations', timeout=10)
    require(response.ok, 'External observation unavailable')
    observation = next(item for item in response.json()['certificates'] if item['certificate_id'] == imported_id)
    require(observation['origin'] == 'external' and observation['renewal_owner'] == 'external'
            and observation['not_after_timestamp_seconds'] == external_cert.not_valid_after_utc.timestamp()
            and observation['issuance_retry_count'] is None, 'External expiry or ownership is incorrect')
    response = requests.get(api + '/api/certificates/metrics', timeout=10)
    require(response.ok and response.headers['Content-Type'].startswith('text/plain'),
            'Metrics is not a raw Prometheus response')
    expected_metric = 'certlord_certificate_not_after_timestamp_seconds{certificate_id="' + imported_id + '"} '
    require(expected_metric + str(external_cert.not_valid_after_utc.timestamp()) in response.text,
            'Prometheus expiry does not match imported leaf')
    require('PRIVATE KEY' not in response.text and external_payload['key'] not in response.text,
            'Metrics exposed private material')
    require(vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['metadata']['version']
            == initial_import['metadata']['version'], 'Observation changed Vault material')
    phase('external-expiry-json-and-prometheus-read-only-observation')

    job = json.loads(job_config.read_text())
    job.update(secret_path=imported_path, domain=external_domain)
    job_config.write_text(json.dumps(job))
    cycle('crawl', 'queue-external-certificate')
    # The product probe runs after the remote job, not merely in this harness.
    # First use a CA which does not trust the imported leaf; retain pending work.
    modconf['tls_verification'] = {'timeout': 3, 'targets': {
        imported_id: {'host': '127.0.0.1', 'port': listener.server_port, 'ca_file': str(trust)}}}
    write_yaml(Path(config_path), config)
    cycle('deploy', 'external-untrusted-destination')
    failed_check = vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['data']
    require(failed_check['status'] == 'generated'
            and failed_check['verification']['status'] == 'failed'
            and failed_check['verification']['error_code'] == 'tls_validation_failed',
            'Untrusted destination was acknowledged as deployed')
    require(pending.smembers(SERVER_ID), 'Failed destination verification lost pending work')
    metadata = requests.get(api + '/api/certificates/' + imported_id, timeout=5).json()
    require(metadata['verification']['status'] == 'failed', 'Verification failure is not visible in API')
    phase('product-tls-verification-rejects-untrusted-destination-and-retains-work')
    modconf['tls_verification']['targets'][imported_id]['ca_file'] = str(tls_cert)
    write_yaml(Path(config_path), config)
    cycle('deploy', 'deploy-external-certificate')
    verified_check = vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['data']
    require(verified_check['status'] == 'deployed'
            and verified_check['verification']['status'] == 'verified'
            and verified_check['verification']['observed_fingerprint_sha256'] == external_cert.fingerprint(hashes.SHA256()).hex(),
            'Product TLS verification did not accept exact trusted leaf')
    require(not pending.smembers(SERVER_ID), 'Verified deployment did not clean pending work')
    metadata = requests.get(api + '/api/certificates/' + imported_id, timeout=5).json()
    require(metadata['verification']['status'] == 'verified', 'Verified result is not visible in API')
    metrics = requests.get(api + '/api/certificates/metrics', timeout=5)
    require(metrics.ok and 'certlord_certificate_tls_verification{certificate_id="' + imported_id
            + '",status="verified"} 1' in metrics.text, 'Verified result is not visible in metrics')
    phase('product-tls-verification-recovery-acknowledges-exact-served-leaf')
    external_stored = vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['data']
    require(external_stored['status'] == 'deployed', 'External certificate not acknowledged')
    require(served_fingerprint(listener.server_port, tls_cert, external_domain)
            == external_cert.fingerprint(hashes.SHA256()).hex(), 'Imported certificate not served over trusted TLS')
    cycle('crawl', 'external-renewal-policy')
    pending_import = pending.get('cert:' + imported_id)
    require(not pending_import or not json.loads(pending_import)['certs'], 'Imported certificate scheduled for ACME renewal')
    require(vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['data']['cert']
            == external_payload['cert'], 'External material changed during renewal scan')
    phase('external-import-auton-deployment-trusted-tls-and-no-acme-renewal')
    replacement_url = api + '/api/certificates/' + imported_id + '/material'
    metadata = requests.get(api + '/api/certificates/' + imported_id, timeout=5).json()
    old_version = metadata['version']

    def replacement_material(days):
        cert = (x509.CertificateBuilder().subject_name(external_cert.subject)
            .issuer_name(issuer.subject).public_key(external_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(external_domain)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256()))
        return {'cert':cert.public_bytes(serialization.Encoding.PEM).decode(),
                'key':external_payload['key'], 'chain':external_payload['chain']}

    candidates = [dict(replacement_material(days), expected_version=old_version) for days in (20,21)]
    require(requests.put(replacement_url, json=replacement_material(22), timeout=10).status_code == 400,
            'Replacement without version accepted')
    barrier = threading.Barrier(2)
    def replace_together(payload):
        barrier.wait(timeout=5)
        return requests.put(replacement_url, json=payload, timeout=15)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(replace_together, candidates))
    winners = [i for i, response in enumerate(results) if response.status_code == 200]
    require(len(winners) == 1 and all(response.status_code in (200,409,503) for response in results),
            'Concurrent replacement did not have exactly one winner')
    winner = winners[0]
    require(requests.put(replacement_url, json=candidates[1-winner], timeout=10).status_code == 409,
            'Stale replacement retry was not rejected')
    replaced = vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']
    require(replaced['metadata']['version'] == old_version + 1 and replaced['data']['cert'] == candidates[winner]['cert'],
            'Concurrent replacement changed material/version unexpectedly')
    require(replaced['data'].get('operation_id') != import_operation_id
            and replaced['data'].get('operation_id') == results[winner].json().get('operation_id'),
            'Replacement did not persist a new operation identity')
    require(replaced['data']['identity_sha256'] == initial_import['data']['identity_sha256'],
            'Replacement changed canonical identity')
    require(results[winner].json()['certificate_id'] == imported_id, 'Replacement changed UUID')
    try:
        vault.secrets.kv.v2.create_or_update_secret(imported_path, secret=external_stored, cas=old_version)
    except hvac.exceptions.InvalidRequest:
        pass
    else:
        raise RuntimeError('Stale deployment snapshot overwrote replacement')
    phase('external-replacement-version-conflict-single-winner-and-stale-ack-rejection')

    (directory / 'injected-failure-executed').unlink(missing_ok=True)
    (directory / 'fail-deployment').touch()
    cycle('crawl', 'queue-replaced-external')
    cycle('deploy', 'fail-replaced-external')
    require((directory / 'injected-failure-executed').exists(), 'Replacement failure did not reach remote job')
    require(served_fingerprint(listener.server_port, tls_cert, external_domain)
            == external_cert.fingerprint(hashes.SHA256()).hex(), 'Failed replacement changed live TLS')
    require(vault.secrets.kv.v2.read_secret_version(imported_path, raise_on_deleted_version=True)['data']['data']['status']
            == 'generated' and pending.scard(SERVER_ID) > 0, 'Failed replacement lost pending deployment')
    (directory / 'fail-deployment').unlink()
    wait_for(lambda: pending.pttl(lease_probe.key) == -2, 'Replacement failure lease expiry', timeout=40)
    cycle('deploy', 'recover-replaced-external')
    winner_cert = x509.load_pem_x509_certificate(candidates[winner]['cert'].encode())
    require(served_fingerprint(listener.server_port, tls_cert, external_domain)
            == winner_cert.fingerprint(hashes.SHA256()).hex(), 'Recovered replacement not served')
    phase('external-replacement-failed-deploy-preserves-live-tls-and-recovers')

    current_meta = requests.get(api + '/api/certificates/' + imported_id, timeout=5).json()
    cli_material = replacement_material(30)
    for field in ('cert','key','chain'):
        Path(external_files[field]).write_text(cli_material[field])
    cli_args = ['certlord','replace',imported_id,'--expected-version',str(current_meta['version']),
        '--url',api,'--json','--cert-file',external_files['cert'],'--key-file',external_files['key'],
        '--chain-file',external_files['chain']]
    cli_replacement = subprocess.run(cli_args, env=env, capture_output=True, timeout=15)
    require(cli_replacement.returncode == 0 and json.loads(cli_replacement.stdout)['certificate_id'] == imported_id,
            'Installed replacement CLI failed')
    require(b'PRIVATE KEY' not in cli_replacement.stdout, 'Replacement CLI exposed material')
    cli_stale = subprocess.run(cli_args, env=env, capture_output=True, timeout=15)
    require(cli_stale.returncode != 0, 'CLI reused stale version successfully')
    cycle('crawl', 'queue-cli-replacement')
    cycle('deploy', 'deploy-cli-replacement')
    cli_cert = x509.load_pem_x509_certificate(cli_material['cert'].encode())
    require(served_fingerprint(listener.server_port, tls_cert, external_domain)
            == cli_cert.fingerprint(hashes.SHA256()).hex(), 'CLI replacement not served')
    current_meta = requests.get(api + '/api/certificates/' + imported_id, timeout=5).json()
    require(current_meta['renewal_owner'] == 'external', 'Replacement changed renewal ownership')
    require(requests.delete(api + '/api/certificates/' + imported_id, timeout=10).ok, 'Removal before replacement failed')
    require(requests.put(replacement_url, json=dict(cli_material, expected_version=current_meta['version']), timeout=10).status_code == 409,
            'Replacement restored pending deletion')
    phase('external-replacement-installed-cli-stale-replay-and-deletion-refusal')


    # Real Redis outage: mutation must fail rather than return success.
    stop(redis_process)
    response = requests.put(api + '/api/certificates/' + CERTIFICATE_ID,
                             json={'domains': [DOMAIN]}, timeout=10)
    require(response.status_code >= 500, 'Redis outage returned success')
    for suffix in ('observations', 'metrics'):
        require(requests.get(api + '/api/certificates/' + suffix, timeout=10).status_code == 503,
                'Redis outage produced a successful supervision response')
    ready = requests.get(api + '/api/health/ready', timeout=10)
    require(ready.status_code == 503 and not ready.json()['dependencies']['redis'],
            'Readiness concealed Redis outage')
    require(requests.get(api + '/api/health/live', timeout=5).ok, 'Redis outage changed API liveness')
    for route in ('/api/operations','/api/operations/metrics'):
        require(requests.get(api + route, timeout=10).status_code == 503,
                'Operations turned Redis outage into empty success')
    phase('redis-outage-rejected')
    report['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'cycle', 'deploy-job', 'dns-daemon'))
    parser.add_argument('--tools', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--cycle', choices=('issue', 'crawl', 'deploy'))
    parser.add_argument('--job-config', type=Path)
    parser.add_argument('--dns-port', type=int)
    parser.add_argument('--pidfile', type=Path)
    parser.add_argument('--logfile', type=Path)
    parser.add_argument('--expect-storage-error', action='store_true')
    parser.add_argument('--systemd-scheduler', action='store_true')
    args = parser.parse_args()
    if args.mode == 'dns-daemon':
        from network_faults import dns_daemon
        return dns_daemon(args)
    if args.mode == 'cycle':
        from certlord.ports.certificates import StorageError
        try:
            worker_cycle(args)
        except StorageError:
            if not args.expect_storage_error:
                raise
            return 0
        require(not args.expect_storage_error, 'Expected storage failure did not occur')
        return 0
    if args.mode == 'deploy-job':
        return deploy_job(args)
    for executable in ('redis-server', 'certbot', 'certlord', 'auton', 'autond'):
        require(shutil.which(executable), 'Missing executable: ' + executable)
    args.source = args.source.resolve(strict=True)
    args.tools = args.tools.resolve(strict=True)
    report = {'status': 'failed', 'passed': [], 'packages': {p: version(p) for p in PACKAGES},
              'limits': ['Full scheduler SIGTERM and deployment SIGKILL recovery; no issuance SIGKILL, host crash or soak acceptance.',
                         'Real HTTPdis Basic on loopback; no bearer/OIDC/TLS-termination acceptance.',
                         'RSA 2048 issuance; no ECDSA or external DNS policy acceptance.',
                         'Silent Vault read timeout and scheduler join budget tested; no bound on every backend/DNS call.',
                         'Sealed disposable Vault tests service unavailability, not network partitions or persistent crash recovery.',
                         'Harness kills local descendants after daemon SIGKILL; this is not automatic parent cleanup.',
                         'Idempotent fixture replay is not remote fencing or exactly-once execution.',
                         'No transactional Vault/Redis acknowledgement guarantee.']}
    if args.systemd_scheduler:
        require(os.environ.get('CERTLORD_DISPOSABLE_SYSTEMD') == '1', 'Disposable systemd marker required')
        report['limits'] = [
            'Installed unit graceful stop during ACME issuance and remote deployment, followed by recovery.',
            'Private Debian 12 container; no host reboot, SIGKILL, backend stall or production soak acceptance.',
            'Other fixture daemons run independently as root; the installed scheduler runs as certlord.',
            'No historical package upgrade, exactly-once remote execution or cross-store atomicity guarantee.']
    try:
        with tempfile.TemporaryDirectory(prefix='certlord-lifecycle-') as temporary, ExitStack() as stack:
            try:
                exercise(args, Path(temporary), stack, report)
            except Exception:
                diagnostics = {}
                for log in Path(temporary).glob('*.log'):
                    locations = []
                    for line in log.read_text(errors='replace').splitlines():
                        match = re.match(r'\s*File "([^"]+)", line ([0-9]+), in ([a-zA-Z_][a-zA-Z_0-9]*)', line)
                        if match:
                            locations.append({'file': Path(match[1]).name,
                                              'line': int(match[2]), 'function': match[3]})
                        elif re.match(r'^[A-Za-z_][A-Za-z_0-9.]*(Error|Exception):', line):
                            locations.append({'exception': line.split(':', 1)[0]})
                    categories = ('Another instance of Certbot is already running',
                                  'Connection refused', 'Max retries exceeded', 'Read timed out',
                                  'Certbot failed to authenticate', 'Some challenges have failed',
                                  'challenge is invalid', 'Error determining zone',
                                  'HTTPError', 'HTTP 503', 'HTTP 401', 'HTTP 403',
                                  'Failed to establish a new connection', 'max retries exceeded',
                                  'Failed to renew', 'Failed to parse', 'does not appear to be running')
                    log_text = log.read_text(errors='replace')
                    matched = [category for category in categories if category in log_text]
                    if locations or matched:
                        diagnostics[log.name] = {'locations': locations[-15:], 'categories': matched}
                report['diagnostics'] = diagnostics
                raise
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
