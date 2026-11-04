"""The daemon must not weaken supervisor or inherited file permissions."""
import grp
import logging
import os
from pathlib import Path
import pwd
import runpy
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch


class DaemonPermissionsTests(unittest.TestCase):
    def setUp(self):
        source_script = Path(__file__).resolve().parents[1] / 'bin' / 'certlord'
        script = str(source_script) if source_script.exists() else shutil.which('certlord')
        self.assertIsNotNone(script, 'Installed certlord executable is required')
        namespace = runpy.run_path(script, run_name='certlord_permission_fixture')
        self.main = namespace['main']
        self.options = SimpleNamespace(username=pwd.getpwuid(os.geteuid()).pw_name,
                                       groupname=grp.getgrgid(os.getegid()).gr_name,
                                       pidfile='/unused.pid', logfile='/unused.log',
                                       conffile='/unused.yml', foreground=True,
                                       loglevel=logging.INFO)
        self.os_calls = MagicMock()
        for name in ('chown', 'initgroups', 'setgid', 'setuid'):
            self.enterContext(patch('os.' + name, getattr(self.os_calls, name)))
        self.daemon = MagicMock()
        self.server = MagicMock()
        self.enterContext(patch.dict(self.main.__globals__, {
            'make_piddir': MagicMock(), 'make_logdir': MagicMock(),
            'init_logger': MagicMock(), 'load_conf': lambda *a, **kw: self.options,
            'httpdis_json': self.server, 'daemonize': self.daemon,
        }))
        self.addCleanup(os.umask, os.umask(0o077))

    def test_root_sets_account_groups_before_changing_identity(self):
        uid, gid = os.geteuid(), os.getegid()
        with patch('os.geteuid', return_value=0):
            self.main(self.options)
        self.assertEqual(self.os_calls.mock_calls, [
            call.chown(self.options.pidfile, uid, gid),
            call.initgroups(self.options.username, gid), call.setgid(gid), call.setuid(uid)])
        self.server.run.assert_called_once_with(self.options)

    def test_nonroot_preserves_supervisor_groups(self):
        with patch('os.geteuid', return_value=1001):
            self.main(self.options)
        self.os_calls.initgroups.assert_not_called()
        self.server.run.assert_called_once_with(self.options)

    def test_group_setup_failure_stops_startup_and_unlocks_pid(self):
        self.os_calls.initgroups.side_effect = PermissionError('initgroups')
        with patch('os.geteuid', return_value=0), self.assertLogs('certlord', 'ERROR'), \
                self.assertRaises(SystemExit) as error:
            self.main(self.options)
        self.assertEqual(error.exception.code, 1)
        self.os_calls.setuid.assert_not_called()
        self.server.run.assert_not_called()
        self.daemon.unlock_pidfile.assert_called_once_with(self.options.pidfile)

    def test_server_exit_status_propagates_after_pid_cleanup(self):
        self.server.run.side_effect = SystemExit(7)
        with self.assertRaises(SystemExit) as error:
            self.main(self.options)
        self.assertEqual(error.exception.code, 7)
        self.daemon.unlock_pidfile.assert_called_once_with(self.options.pidfile)

    def test_permissions_tightened_before_files_and_retained_during_run(self):
        observed = []

        def observe(*args):
            mask = os.umask(0o077)
            os.umask(mask)
            observed.append(mask)

        self.server.run.side_effect = observe
        with patch.dict(self.main.__globals__, {'make_piddir': observe, 'make_logdir': observe}):
            for inherited in (0o022, 0o077, 0o177):
                with self.subTest(inherited=oct(inherited)):
                    observed.clear()
                    os.umask(inherited)
                    self.main(self.options)
                    self.assertEqual(observed, [inherited | 0o077] * 3)
