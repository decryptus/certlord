"""Reject mismatched versions, tags or private documents before publication."""
import ast
import os
from pathlib import Path, PurePosixPath
import tarfile
import zipfile
import yaml

root = Path(__file__).resolve().parents[2]
version = (root / 'VERSION').read_text().strip()
config = yaml.safe_load((root / 'setup.yml').read_text())
assert config['version'] == config['release'] == version
assert (root / 'RELEASE').read_text().strip() == version
module = ast.parse((root / 'bin/certlord').read_text())
cli_version = next(ast.literal_eval(n.value) for n in module.body
                   if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__version__' for t in n.targets))
assert cli_version == version
ref = os.environ.get('GITHUB_REF', '')
if ref.startswith('refs/tags/'):
    assert ref == 'refs/tags/v' + version, (ref, version)
files = sorted((root / 'dist').iterdir())
assert len(files) == 2 and sum(p.suffix == '.whl' for p in files) == 1
assert sum(p.name.endswith('.tar.gz') for p in files) == 1
for path in files:
    assert version in path.name, path.name
    names = zipfile.ZipFile(path).namelist() if path.suffix == '.whl' else tarfile.open(path).getnames()
    for name in names:
        parts = PurePosixPath(name).parts
        assert not name.startswith('/') and '..' not in parts, name
        assert not any(part in {'.git', 'ROADMAP.md', 'SANITIZED-MANIFEST.json', 'pr-history.json', 'evidence', 'framework_candidates'} for part in parts), name
        assert not any(part.startswith(('review-20', 'release-readiness-', 'http-boundary-review-', 'operation-audit-review-')) for part in parts), name
print('Release metadata, tag and distribution inventory verified:', version)
