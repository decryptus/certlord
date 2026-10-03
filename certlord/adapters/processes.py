# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded command execution in an owned POSIX process group."""
import math
import os
import signal
import subprocess
import threading
import time


class CommandInterrupted(Exception):
    pass


class CommandTimeout(Exception):
    pass


class CommandRunner(object):
    def __init__(self, stop_event, timeout, grace):
        if any(not math.isfinite(v) or v <= 0 for v in (timeout, grace)):
            raise ValueError("Command deadlines must be finite and positive")
        self.stop_event = stop_event
        self.timeout, self.grace = timeout, grace
        self._launch_lock = threading.Lock()

    @staticmethod
    def _signal(process, sig):
        try:
            os.killpg(process.pid, sig)
        except OSError:
            if process.poll() is None:
                raise

    def stop(self):
        with self._launch_lock:
            self.stop_event.set()

    def run(self, args, env):
        with self._launch_lock:
            if self.stop_event.is_set():
                raise CommandInterrupted('Worker stopping')
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, start_new_session=True)
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                if self.stop_event.is_set():
                    raise CommandInterrupted('Worker stopping')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandTimeout('Command deadline exceeded')
                try:
                    stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                    if self.stop_event.is_set():
                        raise CommandInterrupted('Worker stopping')
                    return process.returncode, stdout, stderr
                except subprocess.TimeoutExpired:
                    pass
        finally:
            # The session is ours even if the parent exited before descendants.
            self._signal(process, signal.SIGTERM)
            try:
                process.communicate(timeout=self.grace)
            except (subprocess.TimeoutExpired, OSError):
                self._signal(process, signal.SIGKILL)
                try:
                    process.communicate(timeout=self.grace)
                except subprocess.TimeoutExpired:
                    process.stdout.close()
                    process.stderr.close()
                    process.wait(timeout=self.grace)
            finally:
                self._signal(process, signal.SIGKILL)
