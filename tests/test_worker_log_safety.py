"""Untrusted command/backend details must not enter scheduler logs."""
from contextlib import nullcontext
import unittest
from unittest.mock import Mock, patch

from certlord.classes.certbot_handler import SslCertsCertbotHandler
from certlord.classes.deployer import SslCertsDeployer
from certlord.classes.vault_crawler import SslCertsVaultCrawler
from certlord.classes.config import STATUS_CREATE, STATUS_DELETE


SECRET = 'synthetic-secret-do-not-log\nFORGED log entry'


class WorkerLogSafetyTests(unittest.TestCase):
    def issuance_worker(self):
        module = Mock()
        module.modconf = {}
        module.certbot_cmd.return_value = {'args': ['certbot', SECRET], 'env': None}
        worker = SslCertsCertbotHandler(module, Mock())
        worker._runner = Mock()
        return worker, module, Mock()

    def assert_safe(self, captured):
        self.assertNotIn('synthetic-secret', '\n'.join(captured.output))
        self.assertNotIn('FORGED', '\n'.join(captured.output))
        for record in captured.records:
            self.assertIsNone(record.exc_info)

    def test_command_output_and_arguments_not_logged_on_success_or_failure(self):
        for code in (0, 1):
            with self.subTest(code=code):
                worker, module, pending = self.issuance_worker()
                worker._runner.run.return_value = (code, SECRET.encode(), SECRET.encode())
                with patch('certlord.classes.certbot_handler.issuance_command',
                           return_value=nullcontext((['certbot', SECRET], None))), \
                     self.assertLogs('certlord.classes.certbot_handler', level='DEBUG') as logs:
                    worker._create_certs({STATUS_CREATE: ['example.test']}, pending)
                self.assert_safe(logs)
                self.assertIn('exited with code %s' % code, '\n'.join(logs.output))
                (pending.rem_dom if code == 0 else pending.incr_retry).assert_called_once_with('example.test')
                (pending.incr_retry if code == 0 else pending.rem_dom).assert_not_called()
                module.save_acerts.assert_called_once()

    def test_issuance_exception_keeps_retry_without_exception_details(self):
        worker, module, pending = self.issuance_worker()
        module.service.begin_issuance.side_effect = RuntimeError(SECRET)
        with self.assertLogs('certlord.classes.certbot_handler') as logs:
            worker._create_certs({STATUS_CREATE: ['example.test']}, pending)
        self.assert_safe(logs)
        pending.incr_retry.assert_called_once_with('example.test')
        pending.rem_dom.assert_not_called()
        worker._runner.run.assert_not_called()

    def test_removal_exception_keeps_pending_without_exception_details(self):
        worker, module, pending = self.issuance_worker()
        module.delete_certificate.side_effect = RuntimeError(SECRET)
        with self.assertLogs('certlord.classes.certbot_handler') as logs:
            worker._delete_certs({STATUS_DELETE: ['example.test'], 'certificate_id': 'id'}, pending)
        self.assert_safe(logs)
        pending.incr_retry.assert_called_once_with('example.test')
        pending.rem_dom.assert_not_called()
        module.save_acerts.assert_called_once()

    def test_all_worker_cycle_failures_omit_exception_details(self):
        for cls in (SslCertsCertbotHandler, SslCertsVaultCrawler, SslCertsDeployer):
            with self.subTest(worker=cls.__name__):
                worker = cls.__new__(cls)
                worker.killed = False
                worker._stop_event = Mock()
                worker.check_interval = 1
                def fail(*args):
                    worker.killed = True
                    raise RuntimeError(SECRET)
                with patch(cls.__module__ + '.run_cycle', side_effect=fail), \
                     self.assertLogs(cls.__module__) as logs:
                    worker.run()
                self.assert_safe(logs)
                self.assertIn('cycle failed', '\n'.join(logs.output))
