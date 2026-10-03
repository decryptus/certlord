"""Operational reads distinguish outages, missing state and successful emptiness."""
import json
import unittest
from unittest.mock import Mock
from certlord.adapters.operations import operations_snapshot
from certlord.services.runtime import CertificateRuntime
from certlord.services.observations import operations_metrics
from certlord.modules.ssl_certs import SslCertsModule

IDENTITY = '12345678-1111-4111-8111-111111111111'
QUEUE = 'deploy:' + 'a'*64


class OperationsTests(unittest.TestCase):
    def redis(self):
        adapter = Mock()
        connection = Mock()
        adapter.servers = {'fixture':{'conn':connection}}
        connection.scan_iter.return_value = [b'cert:'+IDENTITY.encode()]
        connection.get.return_value = json.dumps({'certs':{'example.test':{'status':'renew','retry':5}}})
        connection.sscan_iter.return_value = [QUEUE,QUEUE]
        connection.hget.return_value = '1'
        connection.pttl.return_value = 2000
        return adapter,connection

    def test_counts_retries_age_and_ttl_without_writes_or_tokens(self):
        adapter,connection = self.redis()
        result = operations_snapshot(adapter,'fixture',10,5)
        self.assertEqual(result['pending_actions']['renew'],1)
        self.assertEqual(result['pending_retry_count'],5)
        self.assertEqual(result['pending_at_retry_limit'],1)
        self.assertEqual(result['deployment_entries'],1)
        self.assertEqual(result['deployment_lease_ttl_seconds'],2)
        self.assertGreater(result['deployment_oldest_age_seconds'],0)
        self.assertNotIn(IDENTITY,json.dumps(result))
        self.assertTrue(all(call[0] in ('scan_iter','get','sscan_iter','hget','pttl') for call in connection.mock_calls))

    def test_empty_queue_has_no_invented_oldest_age(self):
        adapter,connection = self.redis()
        connection.scan_iter.return_value = []
        connection.sscan_iter.return_value = []
        connection.pttl.return_value = -2
        result = operations_snapshot(adapter,'fixture',10,5)
        self.assertEqual(result['deployment_entries'],0)
        self.assertIsNone(result['deployment_oldest_age_seconds'])
        self.assertEqual(result['deployment_lease_state'],'absent')

    def test_missing_timestamp_and_unbounded_lease_are_visible(self):
        adapter,connection = self.redis()
        connection.hget.return_value = None
        connection.pttl.return_value = -1
        result = operations_snapshot(adapter,'fixture',10,5)
        self.assertEqual(result['deployment_missing_timestamps'],1)
        self.assertEqual(result['deployment_lease_state'],'unbounded')
        self.assertIsNone(result['deployment_lease_ttl_seconds'])

    def test_corrupt_state_and_outage_do_not_become_empty_success(self):
        adapter,connection = self.redis()
        for retry in (-1,True,'5'):
            connection.get.return_value = json.dumps({'certs':{'example.test':{'status':'renew','retry':retry}}})
            with self.assertRaises(ValueError):
                operations_snapshot(adapter,'fixture',10,5)
        connection.get.side_effect = RuntimeError('private-connection-string')
        with self.assertRaises(RuntimeError):
            operations_snapshot(adapter,'fixture',10,5)

    def test_observation_limits_fail_instead_of_truncating(self):
        adapter,connection = self.redis()
        connection.scan_iter.return_value = ['cert:legacy','cert:another']
        with self.assertRaises(ValueError):
            operations_snapshot(adapter,'fixture',1,5)
        connection.scan_iter.return_value = []
        connection.sscan_iter.return_value = [QUEUE,'deploy:'+'b'*64]
        with self.assertRaises(ValueError):
            operations_snapshot(adapter,'fixture',1,5)

    def runtime(self):
        runtime = object.__new__(CertificateRuntime)
        runtime._started, runtime._stopping = True,False
        runtime._store, runtime._redis = Mock(),Mock()
        runtime._redis.ping.return_value = {'fixture':True}
        runtime._cycles = None
        runtime._workers = []
        for name in ('certlord-certbot','certlord-crawler','certlord-deployer'):
            worker = Mock()
            worker.name = name
            worker.is_alive.return_value = True
            runtime._workers.append(worker)
        return runtime

    def test_live_never_probes_backends(self):
        runtime = self.runtime()
        self.assertEqual(runtime.live(),{'alive':True,'phase':'running'})
        self.assertEqual(runtime._store.mock_calls,[])
        self.assertEqual(runtime._redis.mock_calls,[])

    def test_ready_requires_workers_backends_and_running_phase(self):
        runtime = self.runtime()
        self.assertTrue(runtime.readiness()['ready'])
        runtime._stopping = True
        self.assertFalse(runtime.readiness()['ready'])
        runtime._stopping = False
        runtime._workers[0].is_alive.return_value = False
        self.assertFalse(runtime.readiness()['ready'])
        runtime._workers[0].is_alive.return_value = True
        runtime._redis.ping.return_value = {'fixture':False}
        self.assertFalse(runtime.readiness()['ready'])
        runtime._store.list_certificate_ids.side_effect = RuntimeError('secret-token')
        result = runtime.readiness()
        self.assertFalse(result['dependencies']['storage'])
        self.assertNotIn('secret-token',json.dumps(result))

    def test_metrics_have_current_gauges_not_lifetime_counters(self):
        adapter,_ = self.redis()
        output = operations_metrics(operations_snapshot(adapter,'fixture',10,5))
        self.assertIn('certlord_pending_actions{state="renew"} 1\n',output)
        self.assertIn('certlord_operations_pending_at_retry_limit 1\n',output)
        self.assertNotIn(QUEUE,output)
        self.assertNotIn(' counter',output)

    def test_health_http_status_and_read_authorization(self):
        module = object.__new__(SslCertsModule)
        module._authorize = Mock()
        module._runtime = Mock()
        module._runtime.readiness.return_value = {'ready':False}
        request = Mock()
        response = module.ready(request)
        self.assertEqual(response.get_code(),503)
        module._authorize.assert_called_once_with(request,'read')
        self.assertEqual(response.get_header('Cache-control'),'no-store')
        module._runtime.reset_mock()
        module._authorize.side_effect = RuntimeError('denied')
        for method in (module.live,module.ready,module.operations,module.operation_metrics):
            with self.assertRaises(RuntimeError):
                method(request)
        self.assertEqual(module._runtime.mock_calls,[])

    def test_observations_share_worker_retry_default_semantics(self):
        from certlord.classes.config import DEFAULT_MAX_RETRIES
        runtime = self.runtime()
        runtime.config = {'general':{'server_id':'fixture'}}
        runtime._operation_scan_limit = 10
        runtime._pending = Mock()
        for configured in (None,0,7):
            runtime.modconf = {'max_retries':configured}
            runtime.operations()
            runtime._pending.operations.assert_called_with('fixture',10,configured or DEFAULT_MAX_RETRIES)
