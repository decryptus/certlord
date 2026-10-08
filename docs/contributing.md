# Contributor documentation

This guide is for people changing or maintaining certlord. For installation, configuration and everyday use, start with the [user documentation](https://github.com/decryptus/certlord/blob/main/README.md).

## Coding conventions

- Four-space indentation, `snake_case` functions/methods, `PascalCase` classes
  and module-level `UPPER_CASE` constants.
- Group standard-library, third-party and project imports. Prefer explicit
  imports in new code; retain framework plugin-registration imports until their
  lifecycle is covered by tests.
- Preserve nearby alignment conventions in legacy code. Keep formatting-only
  changes separate from behavior changes; no repository-wide formatter sweep.
- Keep domain decisions out of HTTP handlers. Services accept ordinary Python
  values; adapters own external libraries and transport-specific details.
- Keep defaults in `classes/config.py`; avoid repeating runtime constants.
- Never mutate request payloads, shared configuration or cached credentials.
- Use argv lists for subprocesses, never a shell string. Do not log credentials
  or certificate private keys.
- Release locks in `finally`/context managers. Test failure paths as well as
  success. Do not silently mark an external operation successful after failure.
- New runtime code keeps the existing Python syntax baseline until a dedicated
  support-policy change is approved. Test tooling uses Python 3.8+; historical
  Python 2.7 metadata is not evidence of current tested support.

## Change process

Use focused PRs, describe behavior and compatibility changes, run the unit and
component contract suites in [testing.md](https://github.com/decryptus/certlord/blob/main/docs/testing.md), and build the source
archive and wheel when packaging or module layout changes. Use synthetic test
credentials and domains. No live integration operation belongs in unit tests.

Architecture and known gaps are in [architecture.md](https://github.com/decryptus/certlord/blob/main/docs/architecture.md),
[components.md](https://github.com/decryptus/certlord/blob/main/docs/components.md) and [testing.md](https://github.com/decryptus/certlord/blob/main/docs/testing.md).


## Development checks

Run both suites with the runtime dependencies installed:

```sh
python -m pip install -r requirements.txt
python .github/scripts/check-test-collection.py --runner unittest tests tests/contracts
python -m unittest discover -s tests -v
python -m unittest discover -s tests/contracts -v
```

Build a source archive and a wheel in an isolated build environment:

```sh
python -m pip install build
python -m build
```

Build dependencies (including PyYAML, needed to read `setup.yml`) are declared
in `pyproject.toml`. Direct dependency floors match the tested baseline in `constraints-minimum.txt`.
CI exercises both that baseline and the latest resolvable dependencies.
Versioned releases publish to PyPI after the test, lifecycle and package checks.
Debian packaging targets Debian 12 / Python 3.11 on amd64. See the
[installation guide](https://github.com/decryptus/certlord/blob/main/docs/debian-installation.md) and validation instructions in
[testing](https://github.com/decryptus/certlord/blob/main/docs/testing.md). Installed-unit start/stop/restart is checked under
disposable systemd PID 1. Controlled stop/restart during issuance and deployment is also verified through
the installed unit. Historical upgrades, host reboot and other distributions
remain separate gates.


## Documentation rules

Keep user instructions and contributor material separate. The repository [engineering requirements](https://github.com/decryptus/certlord/blob/main/AGENTS.md) define the review and validation rules. Preserve user-facing compatibility, security and recovery guidance when moving internal explanations.


## Reproduce the captures

On Linux with Python 3.11/3.12 and DejaVu Sans Mono installed:

```sh
python -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install 'certlord==1.0.0' -r scripts/requirements-docs.txt
python scripts/capture_docs.py --installed
```

Omit `--installed` to capture the checkout client with the environment's installed
dependencies. The script starts and closes a temporary loopback fixture, runs
curses in a pseudo-terminal, interprets the emitted terminal bytes with pyte and
renders those cells with Pillow. It does not draw an invented interface. The CLI
image adds the command prompts around captured stdout. Both image and plain-text
transcript are written to `docs/images`; `capture.json` records version and size.

The documentation workflow regenerates the captures and checks transcripts and
version metadata for drift, then uploads the fresh images for visual inspection.
Pixel rendering can vary with font/system libraries; inspect the images before
updating committed screenshots. Refresh them when UI behavior or examples change.
See [authentication and command options](certificate-identity.md) before connecting
the client to your own service.

## Container maintenance

`Dockerfile` builds the checkout with Python 3.12 and the qualified external
clients. The Docker workflow runs `docker/smoke.sh` on native Linux AMD64 and ARM64
runners before publishing. The smoke check exercises a real Compose installation,
authenticated APIs, scoped Vault access, explicit unseal and persisted data after
restart. It does not qualify arbitrary user deployment scripts or replace the
full Pebble lifecycle workflow.

The Docker Hub repository is `decryptus/certlord`. Publication uses the repository
secret `DOCKERHUB_TOKEN` (a token authorized to push to that repository); credentials
configured in another repository are not inherited. Stable release publication or
the Docker workflow's explicit `publish` input on main enables publication after
both architecture checks succeed. Initial image publication for an existing tag
uses that manual workflow; never move an existing source release tag.

Keep image/version references, Compose templates and the user installation guide
aligned. Base image tags and transitive Python dependencies are not fully locked;
this is not a reproducible/offline build. Rebuild and validate for security updates.
The image embeds `docker/certlord.example.yml`; synchronize it when changing the
main example. Never include `.local/`, user credentials or private acceptance logs
in build contexts, source archives or workflow artifacts.
