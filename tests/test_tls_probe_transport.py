"""Actual TLS handshakes through the installed probe subprocess."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from certlord.adapters.tls_verification import TlsVerifier
from import_fixture import material

IDENTITY = '6ff9418a-a4d7-5964-b0a3-78f920426989'


@contextmanager
def listener(payload):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ('cert', 'key', 'chain'):
            (root/name).write_text(payload[name])
        (root/'cert').write_text(payload['cert']+payload['chain'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'cert',root/'key')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.socket = context.wrap_socket(server.socket,server_side=True)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            yield server.server_port, str(root/'chain')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class TlsTransportTests(unittest.TestCase):
    def verifier(self,port,ca=None):
        target = {'host':'127.0.0.1','port':port}
        if ca:
            target['ca_file'] = ca
        return TlsVerifier({'timeout':3,'targets':{IDENTITY:target}},threading.Event(),0.2)

    def test_trust_hostname_and_exact_leaf_are_all_required(self):
        payload = material()
        with listener(payload) as (port,ca):
            verifier = self.verifier(port,ca)
            self.assertEqual(verifier.verify(IDENTITY,payload['domain'],payload)['status'],'verified')
            self.assertEqual(verifier.verify(IDENTITY,'wrong.example.test',payload)['error_code'],'tls_validation_failed')
            self.assertEqual(verifier.verify(IDENTITY,payload['domain'],material())['error_code'],'fingerprint_mismatch')
            self.assertEqual(self.verifier(port).verify(IDENTITY,payload['domain'],payload)['error_code'],'tls_validation_failed')

    def test_expired_leaf_never_verifies_even_with_matching_fingerprint(self):
        payload = material(offset=-3)
        with listener(payload) as (port,ca):
            result = self.verifier(port,ca).verify(IDENTITY,payload['domain'],payload)
            self.assertEqual(result['error_code'],'tls_validation_failed')

    def test_silent_handshake_is_bounded_by_parent_deadline(self):
        stop = threading.Event()
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                stop.wait(5)
        with socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler) as server:
            thread = threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                verifier = self.verifier(server.server_address[1])
                verifier.runner.timeout = 0.5
                started = time.monotonic()
                result = verifier.verify(IDENTITY,'import.example.test',material())
                self.assertEqual(result['error_code'],'timeout')
                self.assertLess(time.monotonic()-started,3)
            finally:
                stop.set()
                server.shutdown()
                thread.join(timeout=2)
