# Contributing

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
component contract suites in [testing.md](docs/testing.md), and build the source
archive and wheel when packaging or module layout changes. Use synthetic test
credentials and domains. No live integration operation belongs in unit tests.

Architecture and known gaps are in [architecture.md](docs/architecture.md),
[components.md](docs/components.md) and [testing.md](docs/testing.md).
