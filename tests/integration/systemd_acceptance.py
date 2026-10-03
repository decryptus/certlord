#!/usr/bin/env python3
"""Installed Debian package under a real, disposable systemd PID 1.

Run as root inside the private CI container, never against a production host.
No ACME issuance or legacy-package upgrade is claimed by this smoke test.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import time

import hvac
import redis
import requests
import yaml

REPORT = Path('/evidence/systemd.json')
REPORT.parent.mkdir(parents=True, exist_ok=True)
report = {'status': 'failed', 'passed': [], 'limits': [
    'Disposable privileged Debian 12 container, not a VM reboot or production host.',
    'Idle full daemon and challenge preservation, not in-flight ACME/deployment shutdown.',
    'Configured package reinstall, not migration from a historical global-pip installation.',
]}


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=40).strip()


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_for(fn, label, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if fn():
                return
        except (requests.RequestException, redis.RedisError):
            pass
        time.sleep(0.2)
    raise AssertionError('Timed out: ' + label)


def phase(name):
    report['passed'].append(name)
    print('PASS: ' + name, flush=True)


def ready():
    return requests.get('http://127.0.0.1:8666/api/certificates', timeout=1).status_code == 200


def process():
    pid = int(command('systemctl', 'show', 'certlord', '--property=MainPID', '--value'))
    check(pid > 1, 'No service PID')
    check(Path('/proc/%s' % pid).stat().st_uid == pwd.getpwnam('certlord').pw_uid,
          'Daemon is not running as certlord')
    check(int(command('systemctl', 'show', 'certlord', '--property=NRestarts', '--value')) == 0,
          'Unexpected automatic service restart')
    status = Path('/proc/%s/status' % pid).read_text().splitlines()
    mask = int(next(line.split()[1] for line in status if line.startswith('Umask:')), 8)
    check(mask & 0o077 == 0o077, 'Daemon weakened inherited file permissions')
    return pid


def main():
    check(Path('/proc/1/comm').read_text().strip() == 'systemd', 'systemd is not PID 1')
    check(not Path('/etc/certlord/certlord.yml').exists(), 'Unexpected active configuration')
    check(command('systemctl', 'show', 'certlord', '--property=ActiveState', '--value') == 'inactive',
          'Package started without configuration')
    command('systemctl', 'start', 'certlord')
    check(command('systemctl', 'show', 'certlord', '--property=ActiveState', '--value') == 'inactive',
          'Missing configuration did not prevent start')
    phase('systemd-pid1-and-unconfigured-start-condition')

    command('systemctl', 'start', 'redis-server', 'vault-fixture')
    wait_for(lambda: requests.get('http://127.0.0.1:8200/v1/sys/health', timeout=1).ok, 'Vault')
    vault = hvac.Client(url='http://127.0.0.1:8200', token='disposable-systemd-test')
    vault.secrets.kv.v2.create_or_update_secret(path='systemd-preserved/sentinel', secret={'value': 'retained'})
    r = redis.Redis(decode_responses=True)
    wait_for(r.ping, 'Redis')

    source = Path('/usr/share/doc/certlord/examples/certlord.yml')
    if source.exists():
        config = yaml.safe_load(source.read_text())
    else:
        import gzip
        config = yaml.safe_load(gzip.decompress(source.with_suffix('.yml.gz').read_bytes()))
    config['general'].update(listen_addr='127.0.0.1', server_id='systemd-fixture', max_workers=5)
    config['api_authentication'] = {'backend': 'local'}
    config['credentials'] = '/etc/certlord/credentials.yml'
    config['modules']['ssl_certs']['certbot']['become']['enabled'] = False
    credentials = {'vault': {'uri': 'http://127.0.0.1:8200', 'token': 'disposable-systemd-test',
                              'key_name': 'systemd-certificates'},
                   'auton': {'uri': 'http://127.0.0.1:9', 'endpoint': 'unused'}}
    account = pwd.getpwnam('certlord')
    for name, data in [('certlord.yml', config), ('credentials.yml', credentials)]:
        path = Path('/etc/certlord') / name
        path.write_text(yaml.safe_dump(data))
        os.chown(path, 0, account.pw_gid)
        path.chmod(0o640)
    state = Path('/var/lib/certlord/retained-fixture')
    state.write_text('preserved\n')
    os.chown(state, account.pw_uid, account.pw_gid)
    config_path = Path('/etc/certlord/certlord.yml')
    original_config = hashlib.sha256(config_path.read_bytes()).hexdigest()

    command('systemctl', 'start', 'certlord')
    wait_for(ready, 'API ready after service start')
    first_pid = process()
    check(Path('/run/certlord').stat().st_uid == account.pw_uid, 'Runtime directory owner')
    phase('installed-unit-starts-nonroot-full-daemon-and-api')

    challenge = 'A' * 43
    # Exercise the same public challenge route that must survive service restart.
    response = requests.put('http://127.0.0.1:8666/.well-known/acme-challenge/' + challenge,
                            json=challenge + '.' + 'B' * 43, timeout=5)
    check(response.ok, 'Challenge write failed: HTTP %s' % response.status_code)
    challenge_url = 'http://127.0.0.1:8666/.well-known/acme-challenge/' + challenge
    expected = requests.get(challenge_url, timeout=5)
    check(expected.ok and expected.content, 'Challenge read failed')

    started = time.monotonic()
    command('systemctl', 'stop', 'certlord')
    report['stop_seconds'] = round(time.monotonic() - started, 3)
    check(report['stop_seconds'] < 30, 'Stop exceeded supervisor deadline')
    check(command('systemctl', 'show', 'certlord', '--property=Result', '--value') == 'success',
          'Unclean service stop')
    check(not Path('/proc/%s' % first_pid).exists(), 'Stopped process still exists')
    check(not Path('/run/certlord').exists(), 'Runtime directory remained after stop')
    phase('systemctl-stop-clean-within-deadline')

    command('systemctl', 'start', 'certlord')
    wait_for(ready, 'API after stop/start')
    process()
    check(requests.get(challenge_url, timeout=5).content == expected.content, 'Challenge lost after start')
    command('systemctl', 'restart', 'certlord')
    wait_for(ready, 'API after restart')
    process()
    check(requests.get(challenge_url, timeout=5).content == expected.content, 'Challenge lost after restart')
    check(vault.secrets.kv.v2.read_secret_version(path='systemd-preserved/sentinel',
          raise_on_deleted_version=True)['data']['data'] == {'value': 'retained'}, 'Vault state lost')
    phase('systemctl-restart-preserves-challenge-and-backend-state')

    command('systemctl', 'stop', 'certlord')
    package = list(Path('/package').glob('certlord_*.deb'))
    check(len(package) == 1, 'Expected exactly one package')
    command('dpkg', '-i', str(package[0]))
    check(hashlib.sha256(config_path.read_bytes()).hexdigest() == original_config, 'Configuration overwritten')
    check(state.read_text() == 'preserved\n', 'Local state overwritten')
    check(command('systemctl', 'show', 'certlord', '--property=ActiveState', '--value') == 'inactive',
          'Reinstall unexpectedly started service')
    command('systemctl', 'start', 'certlord')
    wait_for(ready, 'API after configured reinstall')
    process()
    check(requests.get(challenge_url, timeout=5).content == expected.content, 'Challenge lost after reinstall')
    command('systemctl', 'stop', 'certlord')
    phase('configured-reinstall-preserves-config-state-and-explicit-start')
    report['status'] = 'passed'


try:
    main()
finally:
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
