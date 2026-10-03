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
from unittest.mock import MagicMock, patch


class DaemonPermissionsTests(unittest.TestCase):
    def test_permissions_tightened_before_files_and_retained_during_run(self):
        source_script = Path(__file__).resolve().parents[1] / 'bin' / 'certlord'
        script = str(source_script) if source_script.exists() else shutil.which('certlord')
        self.assertIsNotNone(script, 'Installed certlord executable is required')
        namespace = runpy.run_path(script, run_name='certlord_permission_fixture')
        main = namespace['main']
        options = SimpleNamespace(username=pwd.getpwuid(os.geteuid()).pw_name,
                                  groupname=grp.getgrgid(os.getegid()).gr_name,
                                  pidfile='/unused.pid', logfile='/unused.log',
                                  conffile='/unused.yml', foreground=True,
                                  loglevel=logging.INFO)
        observed = []

        def observe(*args):
            mask = os.umask(0o077)
            os.umask(mask)
            observed.append(mask)

        replacements = {'make_piddir': observe, 'make_logdir': observe,
                        'init_logger': MagicMock(), 'load_conf': lambda *a, **kw: options,
                        'httpdis_json': SimpleNamespace(init=lambda *a: None, run=observe),
                        'daemonize': MagicMock()}
        saved = os.umask(0o077)
        try:
            with patch.dict(main.__globals__, replacements), patch('os.chown'), \
                    patch('os.setuid'), patch('os.setgid'):
                for inherited in (0o022, 0o077, 0o177):
                    with self.subTest(inherited=oct(inherited)):
                        observed.clear()
                        os.umask(inherited)
                        main(options)
                        self.assertEqual(observed, [inherited | 0o077] * 3)
        finally:
            os.umask(saved)
