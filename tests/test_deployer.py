"""Deployment state must only advance after a successful Auton process."""
import json
import unittest
from unittest.mock import Mock, patch

from certlord.classes.config import DEFAULT_CERTBOT_ARGS, STATUS_DEPLOYED
from certlord.classes.deployer import SslCertsDeployer


class DeployerTests(unittest.TestCase):
    def setUp(self):
        self.module = Mock()
        self.module.modconf = {}
        self.module.config = {'general': {'server_id': 'server-1'}}
        self.module.auton_cmd.return_value = {'args': ['auton'], 'env': {}}
        self.redis = Mock()
        self.redis.servers = {'ssl_certs': {'conn': Mock()}}
        self.snapshot = ({'cert': 'fixture', 'key': 'fixture', 'status': 'generated'}, 7)
        self.module.certificate_snapshot.return_value = self.snapshot
        self.redis.sort.return_value = {'ssl_certs': ['pending-1']}
        self.redis.hget_key.return_value = json.dumps(
            {'certificate_id': '6ff9418a-a4d7-5964-b0a3-78f920426989', 'domain': 'example.org'})
        self.deployer = SslCertsDeployer(self.module, self.redis)
        self.deployer._queue = Mock()
        self.deployer._lease = Mock()
        self.deployer._lease.acquire.return_value = True
        self.deployer._lease.renew.return_value = True

    def assert_pending(self):
        self.module.create_ssl_check.assert_not_called()
        self.module.mark_deployed.assert_not_called()
        self.deployer._lease.acknowledge.assert_not_called()
        self.assertIsNone(self.deployer._proc)

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_launch_failure_preserves_pending_deployment(self, popen):
        popen.side_effect = OSError('executable not found')
        with self.assertLogs('certlord.classes.deployer', level='ERROR'):
            self.deployer._run()
        self.assert_pending()

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_communication_failure_preserves_pending_deployment(self, popen):
        popen.side_effect = OSError('pipe failure')
        with self.assertLogs('certlord.classes.deployer', level='ERROR'):
            self.deployer._run()
        self.assert_pending()

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_nonzero_exit_preserves_pending_deployment(self, popen):
        popen.return_value = (1, b'', b'')
        self.deployer._run()
        self.assert_pending()

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_success_marks_certificate_and_removes_pending_entry(self, popen):
        popen.return_value = (0, b'deployed', b'')
        self.deployer._run()
        self.module.create_ssl_check.assert_called_once_with('example.org')
        self.module.mark_deployed.assert_called_once_with(
            '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', self.snapshot)
        self.deployer._lease.acknowledge.assert_called_once_with('server-1', 'pending-1')

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_storage_failure_after_auton_success_keeps_pending(self, popen):
        from certlord.ports.certificates import StorageError
        popen.return_value = (0, b'', b'')
        self.module.mark_deployed.side_effect = StorageError('Unavailable')
        with self.assertRaises(StorageError):
            self.deployer._run()
        self.deployer._lease.acknowledge.assert_not_called()

    @patch('certlord.classes.deployer.CommandRunner.run')
    def test_empty_startup_does_not_run_auton(self, popen):
        self.redis.sort.return_value = {}
        self.deployer._run(on_start=True)
        popen.assert_not_called()

    def test_certbot_installer_is_a_separate_argument(self):
        index = DEFAULT_CERTBOT_ARGS.index('-i')
        self.assertEqual(DEFAULT_CERTBOT_ARGS[index + 1], 'certbot-httpreq:installer')


if __name__ == '__main__':
    unittest.main()

