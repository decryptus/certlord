"""Disposable loopback fault servers; no production endpoints or credentials."""
import select
import socket
import socketserver
import threading
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import dns.message
import dns.rdatatype
import dns.rrset


class MonitoringFaultServer:
    """Local updown-shaped HTTP fixture, including an applied POST with lost reply."""
    def __init__(self):
        self.blocked = threading.Event()
        self.observed = threading.Event()
        self.release = threading.Event()
        self.drop_create_reply = threading.Event()
        self.lock = threading.Lock()
        self.records = []
        self.creates = 0
        self.listings = 0

    def snapshot(self):
        with self.lock:
            return {'controls': len(self.records), 'creates': self.creates, 'listings': self.listings}

    def server(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, value):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path != '/api/checks':
                    self.send_error(404)
                    return
                with state.lock:
                    state.listings += 1
                if state.blocked.is_set():
                    state.observed.set()
                    state.release.wait(15)
                    self.close_connection = True
                    return
                with state.lock:
                    records = [dict(record) for record in state.records]
                self.reply(records)

            def do_POST(self):
                if self.path != '/api/checks':
                    self.send_error(404)
                    return
                form = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                with state.lock:
                    state.creates += 1
                    record = {'token': str(state.creates), 'url': form['url'][0],
                              'recipients': ['email:123']}
                    state.records.append(record)
                if state.drop_create_reply.is_set():
                    state.drop_create_reply.clear()
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.reply(record)

        return ThreadingHTTPServer(('127.0.0.1', 0), Handler)


class RedisFaultProxy:
    def __init__(self, backend_port):
        self.backend_port = backend_port
        self.blocked = threading.Event()
        self.observed = threading.Event()
        self.release = threading.Event()

    def server(self):
        state = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with socket.create_connection(('127.0.0.1', state.backend_port), timeout=2) as upstream:
                    while True:
                        ready, _, _ = select.select([self.request, upstream], [], [], 0.2)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            if state.blocked.is_set():
                                state.observed.set()
                                state.release.wait(15)
                                # Drop buffered commands/replies, even after recovery. A
                                # timed-out mutation must never be replayed by the fixture.
                                return
                            destination = upstream if source is self.request else self.request
                            destination.sendall(data)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        return Server(('127.0.0.1', 0), Handler)


class DnsFaultServer:
    def __init__(self):
        self.blocked = threading.Event()
        self.observed = threading.Event()

    def server(self):
        state = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, connection = self.request
                if state.blocked.is_set():
                    state.observed.set()
                    return
                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                if query.question[0].rdtype == dns.rdatatype.A:
                    response.answer.append(dns.rrset.from_text(
                        query.question[0].name, 0, 'IN', 'A', '127.0.0.1'))
                connection.sendto(response.to_wire(), self.client_address)

        return socketserver.UDPServer(('127.0.0.1', 0), Handler)


def dns_daemon(args):
    """Run the installed entry point with only its resolver destination injected.

    All lookups still use real dnspython/UDP and the production DnsPolicy, HTTP
    handlers and scheduler. The external ACME client keeps its normal environment.
    """
    import runpy
    import shutil
    import sys
    import dns.resolver

    base = dns.resolver.Resolver

    class FixtureResolver(base):
        def __init__(self, *unused_args, **unused_kwargs):
            super().__init__(configure=False)
            self.nameservers = ['127.0.0.1']
            self.port = args.dns_port

    dns.resolver.Resolver = FixtureResolver
    executable = shutil.which('certlord')
    sys.argv = [executable, '-f', '-c', str(args.config), '-p', str(args.pidfile),
                '--logfile', str(args.logfile)]
    runpy.run_path(executable, run_name='__main__')
