"""Real disposable subprocesses prove deadlines and interruption behavior."""
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch
from certlord.adapters.processes import CommandRunner, CommandInterrupted, CommandTimeout
from certlord.classes.certbot_handler import SslCertsCertbotHandler
from certlord.classes.config import STATUS_CREATE


class ProcessTests(unittest.TestCase):
    def test_success_returns_exit_and_output(self):
        runner = CommandRunner(threading.Event(), 2, 0.3)
        self.assertEqual(runner.run([sys.executable, '-c', 'print("ok")'], None), (0, b'ok\n', b''))

    def test_timeout_kills_process_ignoring_term_and_reaps_it(self):
        runner = CommandRunner(threading.Event(), 0.4, 0.2)
        start = time.monotonic()
        with self.assertRaises(CommandTimeout):
            runner.run([sys.executable, '-c',
                'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'], None)
        self.assertLess(time.monotonic() - start, 3)

    def test_stop_interrupts_running_command(self):
        runner = CommandRunner(threading.Event(), 30, 0.2)
        timer = threading.Timer(0.4, runner.stop)
        timer.start()
        try:
            with self.assertRaises(CommandInterrupted):
                runner.run([sys.executable, '-c', 'import time; time.sleep(30)'], None)
        finally:
            timer.cancel()
            timer.join()

    def test_stopped_runner_never_launches(self):
        runner = CommandRunner(threading.Event(), 1, 0.2)
        runner.stop()
        with self.assertRaises(CommandInterrupted):
            runner.run(['nonexistent-executable'], None)

    def test_invalid_deadlines_rejected(self):
        for value in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                CommandRunner(threading.Event(), value, 1)

    def test_interrupted_issuance_preserves_pending_without_consuming_retry(self):
        module = Mock()
        module.modconf = {}
        module.certbot_cmd.return_value = {'args': ['certbot'], 'env': None}
        worker = SslCertsCertbotHandler(module, Mock())
        worker._runner = Mock()
        worker._runner.run.side_effect = CommandInterrupted()
        pending = Mock()
        from contextlib import nullcontext
        with patch('certlord.classes.certbot_handler.issuance_command',
                   return_value=nullcontext((['certbot'], None))):
            worker._create_certs({STATUS_CREATE: ['example.org']}, pending)
        pending.rem_dom.assert_not_called()
        pending.incr_retry.assert_not_called()
        module.save_acerts.assert_called_once()

    def test_idle_certbot_wait_is_interruptible(self):
        module = Mock()
        module.modconf = {'certbot_check_interval': 300}
        module.certbot_cmd.return_value = {'args': ['certbot'], 'env': None}
        worker = SslCertsCertbotHandler(module, Mock())
        entered = threading.Event()
        worker._run = entered.set
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            worker.terminate()
            worker.join(1)
            self.assertFalse(worker.is_alive())
        finally:
            worker.terminate()
            worker.join(1)

    def test_runtime_signals_all_workers_before_joining(self):
        from certlord.services.runtime import CertificateRuntime
        runtime = CertificateRuntime({'general': {'lock_timeout': 1}}, {},
            Mock(), Mock(), Mock(), Mock(), Mock())
        events = []
        workers = [Mock(name='first'), Mock(name='second')]
        for index, worker in enumerate(workers):
            worker.ident = index + 1
            worker.terminate.side_effect = lambda i=index: events.append(('stop', i))
            worker.join.side_effect = lambda timeout, i=index: events.append(('join', i))
            worker.is_alive.return_value = False
        runtime._workers = workers
        self.assertTrue(runtime.stop())
        self.assertEqual(events, [('stop', 0), ('stop', 1), ('join', 0), ('join', 1)])
