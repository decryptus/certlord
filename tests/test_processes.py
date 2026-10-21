"""Real disposable subprocesses prove deadlines and interruption behavior."""
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch
from certlord.adapters.processes import CommandRunner, CommandInterrupted, CommandTimeout, CommandOutputLimit
from certlord.classes.certbot_handler import SslCertsCertbotHandler
from certlord.classes.config import STATUS_CREATE


class ProcessTests(unittest.TestCase):
    def test_selector_failure_never_starts_external_command(self):
        import errno
        failure = OSError(errno.EMFILE, 'synthetic descriptor exhaustion')
        with patch('certlord.adapters.processes.selectors.DefaultSelector', side_effect=failure), \
                patch('certlord.adapters.processes.subprocess.Popen') as launch:
            with self.assertRaises(OSError) as caught:
                CommandRunner(threading.Event(), 1, .1).run(['synthetic'], None)
        self.assertIs(caught.exception, failure)
        launch.assert_not_called()

    def test_failed_launch_closes_polling_descriptor(self):
        import selectors
        selector = selectors.DefaultSelector()
        with patch('certlord.adapters.processes.selectors.DefaultSelector', return_value=selector):
            with self.assertRaises(FileNotFoundError):
                CommandRunner(threading.Event(), 1, .1).run(
                    ['/synthetic-missing-directory/certlord-test-command'], None)
        self.assertIsNone(selector.get_map())

    def test_failed_pipe_registration_kills_and_reaps_started_child(self):
        import selectors
        import subprocess
        children = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        selector = selectors.DefaultSelector()
        with patch('certlord.adapters.processes.selectors.DefaultSelector', return_value=selector), \
                patch.object(selector, 'register', side_effect=OSError('synthetic registration failure')), \
                patch('certlord.adapters.processes.subprocess.Popen', side_effect=launch):
            with self.assertRaisesRegex(OSError, 'synthetic registration failure'):
                CommandRunner(threading.Event(), 1, .1).run(
                    [sys.executable, '-c', 'import time; time.sleep(30)'], None)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)
        self.assertIsNone(selector.get_map())

    def test_output_limit_covers_each_stream(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), patch('certlord.adapters.processes.MAX_CAPTURE_BYTES', 4096):
                runner = CommandRunner(threading.Event(), 2, .2)
                with self.assertRaises(CommandOutputLimit):
                    runner.run([sys.executable, '-c',
                        'import sys; sys.%s.buffer.write(b"x" * 20000)' % stream], None)

    def test_combined_limit_accepts_exact_boundary_and_rejects_overflow(self):
        with patch('certlord.adapters.processes.MAX_CAPTURE_BYTES', 4096):
            runner = CommandRunner(threading.Event(), 2, .2)
            result = runner.run([sys.executable, '-c',
                'import sys; sys.stdout.buffer.write(b"a"*2048); sys.stderr.buffer.write(b"b"*2048)'], None)
            self.assertEqual(result, (0, b'a' * 2048, b'b' * 2048))
            with self.assertRaises(CommandOutputLimit):
                runner.run([sys.executable, '-c',
                    'import sys; sys.stdout.buffer.write(b"a"*2048); sys.stderr.buffer.write(b"b"*2049)'], None)

    def test_flood_ignoring_term_is_killed_and_reaped(self):
        import subprocess
        processes = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        started = time.monotonic()
        with patch('certlord.adapters.processes.MAX_CAPTURE_BYTES', 4096), \
                patch('certlord.adapters.processes.subprocess.Popen', side_effect=launch):
            with self.assertRaises(CommandOutputLimit):
                CommandRunner(threading.Event(), 3, .1).run([sys.executable, '-c',
                    'import os,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True: os.write(1,b"x"*4096)'], None)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

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
