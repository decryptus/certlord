# CertLord roadmap

Updated: 2026-11-02. Published baseline: 1.0.1.

## Current delivery — 1.1.0 candidate

Named certificate deployment destinations ([issue #10](https://github.com/decryptus/certlord/issues/10)):

- Implemented: explicit per-destination Auton/TLS configuration, generation-bound
  results, persistent submission intent, partial success and targeted retries.
- Implemented: stale-write rejection on replacement/removal, exact served-leaf
  verification, REST/CLI retry and read-only CLI/curses/Textual details.
- Validation in progress: unit/contract suites, installed lifecycle with three
  local TLS endpoints, real Auton, Vault and Redis, and documentation captures.
- Pending: final CI qualification, review, version publication and verification
  of PyPI/Docker Hub and affected documentation/demo/site surfaces.

No public or production certificates are required for these synthetic tests.

## Later work

- Independent multi-CDN TLS checks, separate from deployment targets, with
  explicit connection endpoint, customer SNI and optional exact fingerprint.
- Provider-specific deployment connectors, starting with AWS/CloudFront after
  permissions, region and propagation requirements are qualified.
- External geographic monitoring where provider capabilities permit it; local
  checks do not establish that every CDN point of presence serves the same leaf.

These remain separate future capabilities; named destinations alone do not
implement cloud provisioning, remote fencing or exactly-once execution.
