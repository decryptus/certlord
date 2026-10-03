"""Finite network waits and safe DNS policy failure semantics."""
import socket
import threading
import time
import unittest
from unittest.mock import Mock

import dns.exception
import dns.resolver
import redis

from certlord.adapters.dns_policy import DnsPolicy
from certlord.adapters.redis_client import redis_adapter
from certlord.classes.exceptions import CertLordConfigError
from certlord.services.certificates import CertificateService, CertificateBusy


class BackendTimeoutTests(unittest.TestCase):
    def test_dns_failure_is_not_absent_caa(self):
        resolver = Mock()
        resolver.query.side_effect = dns.resolver.NoNameservers()
        policy = DnsPolicy({'expected_caa_records': [None]}, resolver)
        with self.assertRaises(dns.resolver.NoNameservers):
            policy.check_caa_records('a.example.test')
        self.assertEqual(resolver.query.call_count, 1)

    def test_caa_absence_still_uses_parent_and_policy(self):
        resolver = Mock()
        resolver.query.side_effect = dns.resolver.NoAnswer()
        self.assertTrue(DnsPolicy({'expected_caa_records': [None]}, resolver).check_caa_records('a.test'))
        self.assertEqual(resolver.query.call_count, 2)
        self.assertFalse(DnsPolicy({'expected_caa_records': ['issuer']}, resolver).check_caa_records('a.test'))

    def test_caa_ancestors_share_budget(self):
        resolver = Mock()
        def missing(*args, **kwargs):
            time.sleep(0.06)
            raise dns.resolver.NoAnswer()
        resolver.query.side_effect = missing
        policy = DnsPolicy({'dns_timeout': 0.04, 'expected_caa_records': [None]}, resolver)
        with self.assertRaises(dns.exception.Timeout):
            policy.check_caa_records('a.b.example.test')
        self.assertEqual(resolver.query.call_count, 1)

    def test_dns_backend_error_is_sanitized_and_retryable(self):
        backend = Mock()
        backend.check_dns_resolv.side_effect = RuntimeError('private resolver detail')
        with self.assertRaisesRegex(CertificateBusy, '^DNS validation unavailable$'):
            CertificateService(backend)._validate_domain('example.test')
        backend.check_caa_records.assert_not_called()

    def test_invalid_timeouts_fail_at_configuration(self):
        for value in (0, -1, 'nan', 'inf', None, True, 'bad'):
            with self.subTest(value=value), self.assertRaises(CertLordConfigError):
                DnsPolicy({'dns_timeout': value})
        for query in ('socket_timeout=0', 'socket_timeout=nan', 'socket_connect_timeout=-1', 'retry_on_timeout=True'):
            with self.subTest(query=query), self.assertRaises(CertLordConfigError):
                redis_adapter({'general': {'redis': {'ssl_certs': {'url': 'redis://127.0.0.1/?'+query}}}}, 'ssl_certs')

    def test_real_silent_dns_times_out_then_recovers(self):
        # Real UDP resolver call; synthetic loopback server initially drops responses.
        import dns.message
        import dns.rcode
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        server.settimeout(0.1)
        stop, respond = threading.Event(), threading.Event()
        def serve():
            while not stop.is_set():
                try:
                    data, peer = server.recvfrom(4096)
                except socket.timeout:
                    continue
                if respond.is_set():
                    reply = dns.message.make_response(dns.message.from_wire(data))
                    reply.set_rcode(dns.rcode.NXDOMAIN)
                    server.sendto(reply.to_wire(), peer)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['127.0.0.1']
            resolver.port = server.getsockname()[1]
            policy = DnsPolicy({'dns_timeout': 0.2, 'expected_caa_records': [None]}, resolver)
            started = time.monotonic()
            with self.assertRaises(dns.exception.Timeout):
                policy.check_caa_records('example.test')
            self.assertLess(time.monotonic()-started, 2)
            respond.set()
            self.assertTrue(policy.check_caa_records('example.test'))
        finally:
            stop.set(); worker.join(2); server.close()
        self.assertFalse(worker.is_alive())

    def test_real_silent_redis_times_out_without_replay_then_recovers(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen()
        server.settimeout(0.1)
        stop, respond = threading.Event(), threading.Event()
        commands = []
        errors = []

        def serve():
            try:
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection, connection.makefile('rb') as stream:
                        connection.settimeout(2)
                        while not stop.is_set():
                            line = stream.readline()
                            if not line:
                                break
                            if not line.startswith(b'*'):
                                raise AssertionError('Expected a Redis array')
                            args = []
                            for _ in range(int(line[1:])):
                                size = int(stream.readline()[1:])
                                args.append(stream.read(size))
                                if stream.read(2) != b'\r\n':
                                    raise AssertionError('Malformed Redis request')
                            if args[0].upper() == b'HELLO':
                                connection.sendall(b'%1\r\n+proto\r\n:3\r\n')
                            elif args[0].upper() == b'CLIENT':
                                connection.sendall(b'+OK\r\n')
                            elif args[0].upper() == b'PING':
                                commands.append(args)
                                if respond.is_set():
                                    connection.sendall(b'+PONG\r\n')
                            else:
                                raise AssertionError('Unexpected Redis command')
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        adapter = None
        try:
            url = 'redis://127.0.0.1:%s?socket_timeout=0.2&socket_connect_timeout=0.2' % server.getsockname()[1]
            adapter = redis_adapter({'general': {'redis': {'ssl_certs': {'url': url}}}}, 'ssl_certs')
            started = time.monotonic()
            with self.assertRaises(redis.exceptions.TimeoutError):
                adapter.ping()
            self.assertLess(time.monotonic()-started, 2)
            self.assertEqual(commands, [[b'PING']])
            respond.set()
            self.assertEqual(adapter.ping(), {'ssl_certs': True})
            self.assertEqual(commands, [[b'PING'], [b'PING']])
        finally:
            if adapter is not None:
                adapter.servers['ssl_certs']['conn'].close()
                adapter.servers['ssl_certs']['conn'].connection_pool.disconnect()
            stop.set()
            worker.join(3)
            server.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
