#!/bin/sh
# Disposable CI installation; no real domain or production credentials.
set -eu
docker compose up -d vault redis
docker compose run --rm setup init --email ci@example.invalid
docker compose up -d
for attempt in $(seq 1 60); do
    if docker compose exec -T certlord python /opt/certlord-docker/health.py; then
        break
    fi
    if [ "$attempt" = 60 ]; then
        echo "CertLord readiness failed" >&2
        exit 1
    fi
    sleep 2
done
docker compose exec -T certlord python - <<'PY'
import os
import requests
import yaml
assert os.getuid() == 10001
base = 'http://127.0.0.1:8666'
assert requests.get(base + '/api/certificates', timeout=10).status_code == 401
with open('/etc/certlord/health.yml') as f:
    reader = yaml.safe_load(f)
auth = (reader['user'], reader['password'])
assert requests.get(base + '/api/certificates', auth=auth, timeout=10).status_code == 200
assert requests.post(base + '/api/ssl-certs/deploy', auth=auth, timeout=10).status_code == 403
with open('/etc/certlord/credentials.yml') as f:
    credentials = yaml.safe_load(f)
import hvac
v = credentials['vault']
client = hvac.Client(url=v['uri'])
client.auth.approle.login(v['role_id'], v['secret_id'])
client.secrets.kv.v2.create_or_update_secret(path='certlord-certificates/compose-smoke', secret={'persistent': True})
try:
    client.sys.list_auth_methods()
except hvac.exceptions.Forbidden:
    pass
else:
    raise AssertionError('Runtime Vault credentials can administer Vault')
a = credentials['auton']
import time
for attempt in range(30):
    try:
        if requests.get(a['uri'] + '/health', auth=(a['auth-user'], a['auth-passwd']), timeout=2).status_code == 200:
            break
    except requests.RequestException:
        pass
    time.sleep(1)
else:
    raise AssertionError('Auton did not become ready')
assert requests.get(a['uri'] + '/health', timeout=10).status_code == 401
assert requests.get(a['uri'] + '/health', auth=(a['auth-user'], a['auth-passwd']), timeout=10).status_code == 200
assert not os.path.exists('/bootstrap/vault-recovery.json')
print('Non-root runtime, protected APIs and scoped Vault authentication passed')
PY
docker compose restart vault
docker compose run --rm setup unseal
docker compose restart certlord
for attempt in $(seq 1 60); do
    if docker compose exec -T certlord python /opt/certlord-docker/health.py; then break; fi
    if [ "$attempt" = 60 ]; then exit 1; fi
    sleep 2
done
docker compose exec -T certlord python - <<'PY'
import hvac
import yaml
with open('/etc/certlord/credentials.yml') as f:
    v = yaml.safe_load(f)['vault']
client = hvac.Client(url=v['uri'])
client.auth.approle.login(v['role_id'], v['secret_id'])
data = client.secrets.kv.v2.read_secret_version(path='certlord-certificates/compose-smoke', raise_on_deleted_version=True)
assert data['data']['data']['persistent'] is True
print('Vault restart, explicit unseal and persistent data passed')
PY
