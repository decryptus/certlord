"""CAS and owner-token failures must retain pending deployment work."""
import json
import unittest
from unittest.mock import Mock
import hvac
from certlord.adapters.deployment_lease import DeploymentLease, LeaseLost
from certlord.adapters.vault_store import VaultCertificateStore
from certlord.classes.deployer import SslCertsDeployer
from certlord.ports.certificates import StorageConflict
from certlord.classes.exceptions import CertLordConfigError


class CoordinationTests(unittest.TestCase):
    def worker(self):
        module, redis = Mock(), Mock()
        module.modconf = {}
        module.config = {'general': {'server_id': 'fixture'}}
        module.auton_cmd.return_value = {'args': ['auton'], 'env': {}}
        module.certificate_snapshot.return_value = ({'cert': 'fixture', 'key': 'fixture', 'status': 'generated'}, 3)
        redis.servers = {'ssl_certs': {'conn': Mock()}}
        redis.sort.return_value = {'ssl_certs': ['queued']}
        redis.hget_key.return_value = json.dumps({'certificate_id': '6ff9418a-a4d7-5964-b0a3-78f920426989', 'domain': 'example.org'})
        worker = SslCertsDeployer(module, redis)
        worker._lease = Mock()
        worker._runner = Mock()
        worker._runner.run.return_value = (0, b'', b'')
        return worker, module

    def test_competing_worker_does_not_launch(self):
        worker, module = self.worker()
        worker._lease.acquire.return_value = False
        worker._run()
        worker._runner.run.assert_not_called()
        module.mark_deployed.assert_not_called()

    def test_new_version_during_command_is_not_acknowledged(self):
        worker, module = self.worker()
        module.mark_deployed.side_effect = StorageConflict()
        with self.assertLogs(level='WARNING'):
            worker._run()
        worker._lease.acknowledge.assert_not_called()
        module.create_ssl_check.assert_not_called()
        worker._lease.release.assert_called_once()

    def test_lost_lease_after_command_does_not_write_status(self):
        worker, module = self.worker()
        worker._lease.renew.side_effect = [True, True, False]
        with self.assertRaises(LeaseLost):
            worker._run()
        module.mark_deployed.assert_not_called()
        worker._lease.acknowledge.assert_not_called()

    def test_uncertain_command_retains_lease_until_expiry(self):
        worker, module = self.worker()
        worker._runner.run.return_value = (1, b'', b'')
        worker._run()
        worker._lease.release.assert_not_called()
        module.mark_deployed.assert_not_called()

    def test_vault_cas_uses_snapshot_version(self):
        session = Mock()
        store = VaultCertificateStore(session, 'certs')
        method = session.client.return_value.secrets.kv.v2.create_or_update_secret
        method.side_effect = hvac.exceptions.InvalidRequest('check-and-set parameter did not match')
        with self.assertRaises(StorageConflict):
            store.replace_if_version('6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', 3, {'status': 'deployed'})
        method.assert_called_once_with(path='certs/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org', mount_point='secret',
                                        secret={'status': 'deployed'}, cas=3)

    def test_multiple_redis_servers_fail_closed(self):
        redis = Mock()
        redis.servers = {'one': {}, 'two': {}}
        with self.assertRaises(CertLordConfigError):
            DeploymentLease(redis, 'fixture', 10)

    def test_removed_certificate_is_not_redeployed(self):
        worker, module = self.worker()
        module.certificate_snapshot.return_value = ({'cert': 'fixture', 'status': 'delete'}, 4)
        worker._run()
        worker._runner.run.assert_not_called()
        module.mark_deployed.assert_not_called()
        worker._lease.acknowledge.assert_called_once_with('fixture', 'queued')

    def test_superseded_generation_is_requeued_before_old_entry_cleanup(self):
        worker, module = self.worker()
        worker._queue = Mock()
        worker._redis.hget_key.return_value = json.dumps(
            {'certificate_id': '6ff9418a-a4d7-5964-b0a3-78f920426989', 'domain': 'example.org', 'generation': 'old-generation'})
        worker._run()
        worker._queue.enqueue.assert_called_once()
        worker._lease.acknowledge.assert_called_once_with('fixture', 'queued')
        worker._runner.run.assert_not_called()
        module.mark_deployed.assert_not_called()
