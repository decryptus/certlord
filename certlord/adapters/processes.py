# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded command execution in an owned POSIX process group."""
import math
import os
import selectors
import signal
import subprocess
import threading
import time

MAX_CAPTURE_BYTES = 4 * 1024 * 1024
READ_CHUNK_BYTES = 65536
POLL_SECONDS = 0.2


class CommandInterrupted(Exception):
    pass


class CommandTimeout(Exception):
    pass


class CommandOutputLimit(Exception):
    """Capture exceeded its budget; the external outcome is not confirmed."""


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

    @staticmethod
    def _read_ready(selector, timeout):
        for key, _ in selector.select(timeout):
            data = os.read(key.fd, READ_CHUNK_BYTES)
            if not data:
                selector.unregister(key.fileobj)
            else:
                yield key.data, data

    def _discard(self, selector, timeout):
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            # Cleanup must never accumulate additional command output.
            for _ in self._read_ready(selector, min(POLL_SECONDS, remaining)):
                pass

    def run(self, args, env):
        with self._launch_lock:
            if self.stop_event.is_set():
                raise CommandInterrupted('Worker stopping')
            # Acquire the polling resource before starting any external effect.
            selector = selectors.DefaultSelector()
            try:
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=env, start_new_session=True)
            except BaseException:
                selector.close()
                raise
        deadline = time.monotonic() + self.timeout
        buffers = [bytearray(), bytearray()]
        captured = 0
        try:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while True:
                if self.stop_event.is_set():
                    raise CommandInterrupted('Worker stopping')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandTimeout('Command deadline exceeded')
                for stream, data in self._read_ready(selector, min(POLL_SECONDS, remaining)):
                    captured += len(data)
                    if captured > MAX_CAPTURE_BYTES:
                        raise CommandOutputLimit('Command output limit exceeded')
                    buffers[stream].extend(data)
                if not selector.get_map() and process.poll() is not None:
                    if self.stop_event.is_set():
                        raise CommandInterrupted('Worker stopping')
                    if time.monotonic() >= deadline:
                        raise CommandTimeout('Command deadline exceeded')
                    return process.returncode, bytes(buffers[0]), bytes(buffers[1])
        finally:
            # The session is ours even if the parent exited before descendants.
            self._signal(process, signal.SIGTERM)
            try:
                self._discard(selector, self.grace)
                process.wait(timeout=self.grace)
            except (subprocess.TimeoutExpired, OSError):
                self._signal(process, signal.SIGKILL)
            finally:
                self._signal(process, signal.SIGKILL)
                selector.close()
                process.stdout.close()
                process.stderr.close()
                process.wait(timeout=self.grace)
