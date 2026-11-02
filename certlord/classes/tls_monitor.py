"""Single bounded worker for read-only TLS observations."""
import logging
import threading
from certlord.services.cycle_progress import run_cycle

LOG = logging.getLogger(__name__)


class TlsMonitor(threading.Thread):
    def __init__(self, service, interval, stop_event, wake):
        super().__init__(name='certlord-tls-monitor')
        self.service, self.interval = service, interval
        self.stop_event, self.wake = stop_event, wake
        self.killed = False

    def _run(self):
        return self.service.check(self.stop_event.is_set)

    def run(self):
        while not self.killed:
            self.wake.clear()
            try:
                run_cycle(self)
            except Exception:
                if not self.killed:
                    LOG.error('Independent TLS observation cycle failed')
            if not self.killed:
                self.wake.wait(self.interval)

    def terminate(self):
        self.killed = True
        self.stop_event.set()
        self.wake.set()
