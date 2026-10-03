"""Test-only process facade for the installed unit in an explicit disposable host."""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time


def systemctl(*args):
    return subprocess.check_output(['systemctl', *args], text=True,
                                   stderr=subprocess.STDOUT, timeout=35).strip()


class SystemdProcess:
    def __init__(self, config_path, directory, env, report):
        if os.environ.get('CERTLORD_DISPOSABLE_SYSTEMD') != '1' or os.geteuid() != 0:
            raise RuntimeError('Systemd lifecycle requires the disposable root CI container')
        if Path('/proc/1/comm').read_text().strip() != 'systemd':
            raise RuntimeError('systemd is not PID 1')
        account = pwd.getpwnam('certlord')
        # Synthetic fixture files must be usable by the real service account.
        # Other fixture servers remain independent processes outside its cgroup.
        for path in [directory, *directory.rglob('*')]:
            if not path.is_symlink():
                os.chown(path, account.pw_uid, account.pw_gid)
        target = Path('/etc/certlord/certlord.yml')
        target.write_bytes(Path(config_path).read_bytes())
        os.chown(target, 0, account.pw_gid)
        target.chmod(0o640)
        environment = {'REQUESTS_CA_BUNDLE': env['REQUESTS_CA_BUNDLE'],
                       'CERTLORD_LOGFILE': str(directory / 'scheduler-daemon.log')}
        Path('/etc/certlord/envfile').write_text(''.join(
            key + '=' + json.dumps(value) + '\n' for key, value in environment.items()))
        systemctl('start', 'certlord')
        self.pid = int(systemctl('show', 'certlord', '--property=MainPID', '--value'))
        if self.pid <= 1:
            raise RuntimeError('Installed systemd unit did not start')
        self.report = report
        self.stopped = False
        if Path('/proc/%d' % self.pid).stat().st_uid != account.pw_uid:
            raise RuntimeError('Installed service did not use certlord identity')

    def poll(self):
        if self.stopped:
            return 0
        pid = int(systemctl('show', 'certlord', '--property=MainPID', '--value'))
        return None if pid == self.pid else 1

    def send_signal(self, signum):
        if signum != signal.SIGTERM:
            raise RuntimeError('Only controlled systemctl stop is accepted here')
        started = time.monotonic()
        systemctl('stop', 'certlord')
        elapsed = time.monotonic() - started
        if systemctl('show', 'certlord', '--property=Result', '--value') != 'success':
            raise RuntimeError('systemctl stop was not successful')
        self.report.setdefault('systemd_stop_seconds', []).append(round(elapsed, 3))
        self.stopped = True

    def wait(self, timeout):
        return self.poll()

    def cleanup(self):
        if self.poll() is None:
            systemctl('stop', 'certlord')
            self.stopped = True
