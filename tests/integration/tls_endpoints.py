"""Installed independent TLS checks against local endpoints and real Redis."""
import json
import subprocess
import time
from pathlib import Path
import requests
from certlord.adapters.redis_client import redis_adapter
from certlord.adapters.tls_endpoints import EndpointPlan, EndpointStore
from certlord.services.tls_endpoints import digest


def exercise(config, config_path, daemon, restart, api, ports, domain, ca_file,
             expected, detail, counts, env, phase):
    from lifecycle import write_yaml, wait_for, require, stop
    base = {'host': '127.0.0.1', 'port': ports['west'], 'server_name': domain, 'ca_file': str(ca_file)}
    definitions = {'web': base, 'pinned': dict(base, expected_fingerprint_sha256=expected),
        'wrong-pin': dict(base, expected_fingerprint_sha256='0'*64),
        'wrong-name': dict(base, server_name='wrong.example.test'),
        'untrusted': {key: value for key, value in base.items() if key != 'ca_file'}}
    monitoring = {'interval': 300, 'timeout': 3, 'endpoints': definitions}
    module = config['modules']['ssl_certs']
    module['tls_monitoring'] = monitoring
    # Earlier deployment phases explicitly run cycles with startup disabled.
    # This phase exercises the production scheduler and its optional fourth worker.
    module['routes']['index'].update(at_start=True, at_stop=True)
    module.update(renew_before_expiry=1, certbot_check_interval=300,
                  vault_check_interval=300, deployer_check_interval=300)
    write_yaml(Path(config_path), config)
    before, jobs = detail(), counts()
    daemon = restart(daemon)
    def snapshot():
        response = requests.get(api + '/api/tls-endpoints', timeout=5)
        require(response.ok and response.headers.get('Cache-Control') == 'no-store', 'TLS observation read failed')
        return response.json()
    wait_for(lambda: all(row['checked_at'] for row in snapshot()['endpoints']), 'Independent TLS cycle', [daemon])
    value = snapshot()
    require(value['status'] == 'partial' and value['verified'] == 2 and value['total'] == 5,
            'Independent TLS results confused failed and verified targets')
    rows = {row['name']: row for row in value['endpoints']}
    require(rows['web']['observed_fingerprint_sha256'] == expected, 'Unpinned read missed actual served leaf')
    require(rows['wrong-pin']['error_code'] == 'fingerprint_mismatch', 'Wrong pin accepted')
    require(rows['wrong-name']['error_code'] == rows['untrusted']['error_code'] == 'tls_validation_failed',
            'Trust or hostname validation bypassed')
    require(detail() == before and counts() == jobs, 'Independent reads mutated certificates or deployed jobs')
    ready = requests.get(api + '/api/health/ready', timeout=5).json()
    require(ready['ready'] and ready['workers'].get('certlord-tls-monitor'), 'TLS worker missing from readiness')
    for command in ('tls-endpoints', 'check-tls'):
        result = subprocess.run(['certlord', command, '--url', api, '--json'], env=env,
                                capture_output=True, timeout=15)
        require(result.returncode == 0, 'Installed independent TLS command failed')
        parsed = json.loads(result.stdout)
        require(parsed.get('total') == 5 if command == 'tls-endpoints' else parsed.get('accepted'),
                'Installed TLS CLI returned unexpected result')
    old = rows['web']['checked_at']
    wait_for(lambda: snapshot()['endpoints'][0]['checked_at'] > old, 'Requested TLS cycle', [daemon])
    require(requests.post(api + '/api/tls-endpoints/check', json={'host': 'unconfigured.example.test'},
                         timeout=5).status_code == 400, 'API accepted an arbitrary probe target')
    require(detail() == before and counts() == jobs, 'Requested checks mutated lifecycle state')
    phase('independent-tls-real-trust-sni-pin-cli-worker-without-lifecycle-mutation')

    # Durable evidence and ordering are tested while the writer is stopped.
    stop(daemon)
    plan = EndpointPlan(monitoring)
    store = EndpointStore(redis_adapter(config, 'ssl_certs'), config['general']['server_id'], plan.stale_after)
    signature = digest(plan.targets['web'])
    record = store.read('web', signature)
    require(record['status'] == 'verified', 'TLS evidence was not durable')
    require(not store.write('web', signature, dict(record, started_at=record['started_at']-100,
        status='failed', error_code='timeout')), 'Late observation overwrote newer evidence')
    require(store.read('web', signature) == record, 'Rejected late write changed evidence')
    require(store.connection().ttl(store.key('web', signature)) > 0, 'TLS evidence has no expiry')
    # Inject old synthetic evidence to exercise the same read path after restart.
    stale = dict(record, checked_at=time.time()-plan.stale_after-1)
    store.connection().set(store.key('web', signature), json.dumps(stale), ex=3600)
    from certlord.services.tls_endpoints import EndpointObservations, endpoint_metrics
    observations = EndpointObservations(plan.targets, store, None, plan.stale_after)
    stale_view = observations.snapshot()
    require(stale_view['endpoints'][0]['status'] == 'stale', 'Old stored success appears current')
    require('certlord_tls_endpoint_verified{endpoint="web"} 0' in endpoint_metrics(stale_view), 'Stale evidence remains green')
    definitions['web']['port'] = ports['east']
    changed_plan = EndpointPlan(monitoring)
    require(store.read('web', digest(changed_plan.targets['web'])) is None, 'Changed endpoint reused old evidence')
    write_yaml(Path(config_path), config)
    daemon = restart(daemon)
    wait_for(lambda: snapshot()['verified'] == 2, 'Restarted TLS observations', [daemon])
    metrics = requests.get(api + '/api/tls-endpoints/metrics', timeout=5)
    require(metrics.ok and 'certlord_tls_endpoint_verified{endpoint="web"} 1' in metrics.text,
            'Fresh independent metrics missing')
    require(detail() == before and counts() == jobs, 'TLS restart replayed lifecycle actions')
    phase('independent-tls-durable-ordering-expiry-staleness-reconfiguration-and-restart')
    return daemon
