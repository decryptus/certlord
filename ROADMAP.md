# CertLord roadmap

Updated: 2026-11-03. Published stable release: 1.2.0.

## Post-1.2.0 — ACME acceptance reliability

- Reproduced the HTTP-01 negative-case failure by forcing valid authorization
  reuse. Pebble 2.10.1's zero-percent setting still permits 1% reuse; a reused
  authorization bypasses the challenge expected by both fault scenarios.
  The old failure reports lack sufficient Certbot diagnostics to attribute every
  historical failure conclusively.
- Implemented deterministic reuse followed by explicit ACME authorization
  deactivation in the disposable fixture. Actual rejected/in-flight HTTP-01,
  interrupted pending work and recovery assertions remain enforced in both
  ordinary and systemd lifecycle runs.
- Added sanitized nested/rotated Certbot diagnostics and three regression cases
  covering inclusion, credential exclusion and bounded traceback locations.
- Validation and merge status are tracked in the maintenance pull request.
- Delivery scope: test harness and contributor documentation only. Published
  PyPI/Docker Hub 1.2.0 artifacts, registry descriptions, user guides, Compose
  pins, UI captures, demos and bilingual product websites remain applicable and
  unchanged; no runtime release or service deployment is needed.

## Delivered — 1.2.0

Independent TLS checks of configured endpoints: web servers, reverse proxies,
load balancers and CDNs. CDN is one example, not a provider requirement.

- Merged in [PR #13](https://github.com/decryptus/certlord/pull/13): explicit connection address and TLS name, optional exact
  fingerprint, bounded worker, durable observations, freshness, API/CLI/TUI and metrics.
- Validated: 279 unit cases, 11 component contracts, 2 Textual cases, and the
  82-stage installed lifecycle with real Vault/Redis/Auton and local TLS endpoints.
  Python 3.11/3.12 minimum/latest, installed package, Debian/systemd, amd64/arm64
  Compose, strict documentation and source-archive captures pass. The main release
  run required retries of two existing ACME integration scenarios after initial
  failures; final runs pass with no assertion disabled. Their intermittent cause
  is not established by this delivery.
- Published: [GitHub release](https://github.com/decryptus/certlord/releases/tag/v1.2.0)
  and matching PyPI wheel/source artifacts. Downloaded SHA-256 values match the
  GitHub release assets. Docker Hub versioned/latest tags match, include amd64
  and arm64, and the registry overview matches the source. Image manifest:
  `sha256:d42a22a03017e2d9e0ab74d1faf25eaa2d9bc663d2cd55083931cd41d070fce9`.
- Deployed: bilingual [website PR #23](https://github.com/decryptus/atraxis-site/pull/23).
  Both public pages show 1.2.0 and link the new guide; the deployed capture's
  SHA-256 matches the repository. Pages deployment and final browser CI pass.
- Updated: configuration/migration/user and contributor documentation, versioned
  installation/Compose examples, CLI/curses/Textual captures and reproducible
  source-archive inputs. Website changes are tracked in
  [PR #23](https://github.com/decryptus/atraxis-site/pull/23). Its final browser
  checks pass for both languages at desktop/mobile widths, including the real
  demo HTTPS feed and authentication boundary after a transient feed outage.
- No public certificate or provider account is required for the local fixtures.
- Limits: one local observation location, static optional pins (updated deliberately
  on rotation), no cloud provisioning or geographic propagation guarantee. Existing
  daemon dependencies remain required; monitoring is disabled by default.

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
