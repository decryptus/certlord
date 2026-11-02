"""Exercise actual command dispatch, including installed-package test runs."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from certlord.client import COMMANDS


class ClientEntrypointTests(unittest.TestCase):
    def test_every_client_command_reaches_its_parser_without_daemon_configuration(self):
        source = Path(__file__).resolve().parents[1] / 'bin/certlord'
        entrypoint = str(source) if source.is_file() else shutil.which('certlord')
        self.assertIsNotNone(entrypoint, 'Installed certlord executable must exist')
        env = os.environ.copy()
        if source.is_file():
            # Source CI installs dependencies first; the installed suite has no
            # bin/ checkout and must resolve the package from site-packages.
            env['PYTHONPATH'] = str(source.parent.parent)
        with tempfile.TemporaryDirectory() as directory:
            for command in COMMANDS:
                with self.subTest(command=command):
                    result = subprocess.run([sys.executable, entrypoint, command, '--help'],
                        cwd=directory, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('usage: certlord ' + command, result.stdout)
                    self.assertIn('--url', result.stdout)
                    self.assertNotIn('--conffile', result.stdout)
                    if command == 'retry-destination':
                        self.assertIn('--expected-version', result.stdout)
                        self.assertIn('--acknowledge-uncertain', result.stdout)
