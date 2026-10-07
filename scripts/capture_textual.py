"""Capture actual Textual widgets with synthetic data; no production service."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import dwho.tui.textual
import json
import os
os.environ.pop("NO_COLOR", None)
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from certlord.client.textual_tui import CertificateApp
RECORDS = [
    {'certificate_id': '12a45b78-1234-4234-8234-123456789abc',
     'domains': ['www.example.org'], 'status': 'deployed'},
    {'certificate_id': '34c56d90-1234-4234-8234-123456789abc',
     'domains': ['api.example.org'], 'status': 'generated'},
    {'certificate_id': '56e78f12-1234-4234-8234-123456789abc',
     'domains': ['shop.example.org'], 'status': 'processing'},
]


class DemoClient:
    def inventory(self):
        return RECORDS
    def detail(self, identity):
        return next(record for record in RECORDS if record['certificate_id'] == identity)


async def capture(output, png=False):
    output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    app = CertificateApp(DemoClient(), demo=True)
    async with app.run_test(size=(140, 38)) as pilot:
        await pilot.pause()
        save(app, output, 'textual-inventory', artifacts, png)
        await pilot.press('enter'); await pilot.pause()
        save(app, output, 'textual-details', artifacts, png)

    sources = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in (ROOT / 'certlord').rglob('*.py')}
    try:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True))
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = None, True
    (output / 'textual-manifest.json').write_text(json.dumps(dict(synthetic=True,
        renderer='Textual', textual_version=importlib.metadata.version('textual'),
        dwho_version=importlib.metadata.version('dwho'),
        shared_source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in Path(dwho.tui.textual.__file__).parent.glob('*.py')}, source_revision=revision, dirty=dirty, source_sha256=sources, captures=artifacts), indent=2)+'\n')


def save(app, output, name, artifacts, png):
    path = output / (name + '.svg')
    path.write_text(app.export_screenshot(title='CertLord · SYNTHETIC DEMO'))
    artifacts.append(dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    if png:
        import resvg_py
        rendered = path.with_suffix('.png')
        rendered.write_bytes(resvg_py.svg_to_bytes(svg_path=str(path), monospace_family='DejaVu Sans Mono'))
        artifacts.append(dict(file=rendered.name, sha256=hashlib.sha256(rendered.read_bytes()).hexdigest()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--png', action='store_true')
    args = parser.parse_args()
    asyncio.run(capture(args.output, args.png))
