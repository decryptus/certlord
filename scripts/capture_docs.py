"""Capture real CLI/curses output against a loopback, read-only HTTP fixture.

This is documentation rendering, not certificate lifecycle acceptance.
No daemon, Vault, Redis, credentials or certificate keys are used.
"""
import argparse
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
COLS, ROWS = 100, 12
FONT = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'
RECORDS = [
    {'certificate_id': '12a45b78-1234-4234-8234-123456789abc',
     'domains': ['www.example.org'], 'status': 'deployed'},
    {'certificate_id': '34c56d90-1234-4234-8234-123456789abc',
     'domains': ['api.example.org'], 'status': 'generated'},
    {'certificate_id': '56e78f12-1234-4234-8234-123456789abc',
     'domains': ['shop.example.org'], 'status': 'processing'},
]


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/certificates':
            value = RECORDS
        else:
            value = next((r for r in RECORDS if self.path ==
                          '/api/certificates/' + r['certificate_id']), None)
        data = json.dumps(value).encode()
        self.send_response(200 if value is not None else 404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


def render(screen, destination, name):
    font = ImageFont.truetype(FONT, 18)
    image = Image.new('RGB', (COLS * 11 + 32, ROWS * 24 + 32), '#101014')
    draw = ImageDraw.Draw(image)
    for row in range(ROWS):
        for col in range(COLS):
            char = screen.buffer[row][col]
            # The current client uses default colors and reverse selection only.
            # Fail rather than silently changing future success/error colors.
            if char.fg not in ('default', 'white') or char.bg not in ('default', 'black'):
                raise RuntimeError('Update renderer for new terminal colors')
            fg, bg = '#dddddd', '#101014'
            if char.reverse:
                fg, bg = bg, fg
            x, y = 16 + col * 11, 16 + row * 24
            draw.rectangle((x, y, x + 10, y + 23), fill=bg)
            draw.text((x, y), char.data, font=font, fill=fg)
    image.save(destination / (name + '.png'))
    (destination / (name + '.txt')).write_text(
        '\n'.join(line.rstrip() for line in screen.display).rstrip() + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true',
                        help='Capture the installed package instead of the checkout')
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/images')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    executable = Path(sys.executable).parent / 'certlord' if args.installed else ROOT / 'bin/certlord'
    command = [sys.executable, str(executable)]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CERTLORD_', 'PYTHONPATH'))}
    env.update(TERM='xterm', LC_ALL='C.UTF-8')
    if not args.installed:
        env['PYTHONPATH'] = str(ROOT)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env['CERTLORD_API_URL'] = 'http://127.0.0.1:%d' % server.server_port
    process = None
    master = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            # Run outside checkout, including the installed-package capture.
            screen = pyte.Screen(COLS, ROWS)
            stream = pyte.ByteStream(screen)
            for argv in (['list'], ['show', 'www.example.org']):
                result = subprocess.run(command + argv, env=env, cwd=directory,
                                        capture_output=True, timeout=10, check=True)
                if result.stderr:
                    raise RuntimeError(result.stderr.decode())
                stream.feed(('$ certlord ' + ' '.join(argv) + '\r\n').encode())
                stream.feed(result.stdout.replace(b'\n', b'\r\n') + b'\r\n')
            render(screen, args.output, 'cli-certificates')
            machine = subprocess.run(command + ['list', '--json'], env=env, cwd=directory,
                                     capture_output=True, timeout=10, check=True)
            if json.loads(machine.stdout) != RECORDS:
                raise RuntimeError('JSON inventory differs from fixture')
            nonterminal = subprocess.run(command + ['tui'], env=env, cwd=directory,
                                        capture_output=True, timeout=10)
            if nonterminal.returncode == 0 or b'interactive terminal' not in nonterminal.stderr:
                raise RuntimeError('TUI must reject noninteractive execution')
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))
            try:
                process = subprocess.Popen(command + ['tui'], env=env, cwd=directory,
                                           stdin=slave, stdout=slave, stderr=slave)
            finally:
                os.close(slave)
            screen = pyte.Screen(COLS, ROWS)
            stream = pyte.ByteStream(screen)

            def wait_for(text):
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        stream.feed(os.read(master, 65536))
                    if text in '\n'.join(screen.display):
                        while select.select([master], [], [], 0.1)[0]:
                            stream.feed(os.read(master, 65536))
                        return
                raise RuntimeError('Missing terminal text: ' + text)

            wait_for('shop.example.org')
            render(screen, args.output, 'tui-inventory')
            os.write(master, b'\n')
            wait_for('UUID: ' + RECORDS[0]['certificate_id'])
            render(screen, args.output, 'tui-details')
            os.write(master, b'q')
            wait_for('shop.example.org')
            os.write(master, b'q')
            if process.wait(timeout=3) != 0:
                raise RuntimeError('TUI failed')
        metadata = {'data': 'synthetic read-only HTTP fixture; not lifecycle evidence',
                    'version': importlib.metadata.version('certlord') if args.installed
                    else (ROOT / 'VERSION').read_text().strip(),
                    'dwho': importlib.metadata.version('dwho'),
                    'columns': COLS, 'rows': ROWS}
        (args.output / 'capture.json').write_text(json.dumps(metadata, indent=2) + '\n')
        print('Captured CLI, TUI inventory and details; JSON and noninteractive checks passed.')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if master is not None:
            os.close(master)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == '__main__':
    main()
