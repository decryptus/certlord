# CertLord roadmap

Updated: 2026-11-02. Published stable release: 1.1.0.

## In progress — 1.2.0

Independent TLS checks of configured endpoints: web servers, reverse proxies,
load balancers and CDNs. CDN is one example, not a provider requirement.

- Implemented locally: explicit connection address and TLS name, optional exact
  fingerprint, bounded worker, durable observations, freshness, API/CLI/TUI and metrics.
- Validation and release synchronization are in progress; not yet published.
- No public certificate or provider account is required for the local fixtures.

## Delivered — 1.1.0

Named certificate deployment destinations ([issue #10](https://github.com/decryptus/certlord/issues/10)):

- Released: explicit per-destination Auton/TLS configuration, generation-bound
  results, persistent submission intent, partial success and targeted retries.
- Released: stale-write rejection on replacement/removal, exact served-leaf
  verification, REST/CLI retry and read-only CLI/curses/Textual details.
- Validated: 268 unit cases and 11 component contracts on Python 3.11/3.12,
  including installed-package execution outside the checkout. The optional
  Textual test passes; the 19 CI-helper cases have one intentional pytest-only skip.
- Validated: 80 installed lifecycle stages with real Auton, Vault and Redis,
  including three local TLS endpoints, partial failure, restart, targeted retry
  and replacement. Debian installation/systemd recovery and Docker Compose on
  amd64/arm64 pass.
- Published: [GitHub release](https://github.com/decryptus/certlord/releases/tag/v1.1.0),
  [PyPI wheel and source archive](https://pypi.org/project/certlord/1.1.0/) and
  [Docker Hub](https://hub.docker.com/r/decryptus/certlord/tags). Downloaded PyPI
  hashes match the GitHub assets; versioned and latest Docker tags match and
  contain both architectures. Registry documentation matches the source.
- Updated: user/contributor documentation, Compose and Debian version pins,
  CLI/curses/Textual synthetic captures, reproducible source-archive inputs and
  the existing [English](https://atraxis.io/certlord.html) and
  [French](https://atraxis.io/certlord-fr.html) product pages. Website browser
  checks cover desktop/mobile and language switching; deployed pages and the
  shared capture were checked directly.

Implementation: [PR #12](https://github.com/decryptus/certlord/pull/12), release
commit `7018ece5fea87762aee281c73088d0a0e585d2aa`.
Website: [atraxis-site #22](https://github.com/decryptus/atraxis-site/pull/22).

Existing Atraxis/Atropos demo service pins remain unchanged; this delivery updates
the CertLord demonstration captures and product pages. Named deployment is opt-in
and does not configure or upgrade an existing production daemon.

No public or production certificates are required for these synthetic tests.

## Later work

- Provider-specific deployment connectors, starting with AWS/CloudFront after
  permissions, region and propagation requirements are qualified.
- External geographic monitoring where provider capabilities permit it; local
  checks do not establish that every CDN point of presence serves the same leaf.

These remain separate future capabilities; named destinations alone do not
implement cloud provisioning, remote fencing or exactly-once execution.
