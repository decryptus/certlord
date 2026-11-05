# CertLord roadmap

Updated: 2026-11-05. Published stable release: 1.3.1.

## Delivered — 1.3.1

The issuance worker scans pending Redis records incrementally and guards cleanup
against concurrent updates. The dependency floors include the HTTPdis request
handling fixes and Sonicprobe atomic file replacement. See the
[release notes](docs/release-notes.md) and [Redis ACL upgrade step](MIGRATION.md#redis-permissions-for-131).

The [1.3.1 release](https://github.com/decryptus/certlord/releases/tag/v1.3.1)
passed the minimum/latest dependency, Debian, lifecycle and two-architecture
Compose checks. The downloaded PyPI wheel and source archive match the GitHub
release SHA-256 digests. Docker Hub tags `1.3.1` and `latest` shared manifest
`sha256:68e9607dc083d2d18b4249abd0d3690e8fbd0ad47a0f330a20bdbb479a73bc0f`
for Linux amd64 and arm64 at publication. The registry description matched the
released source. The public [French](https://atraxis.io/certlord-fr.html) and
[English](https://atraxis.io/certlord.html) installation guides serve the
versioned Compose command and Redis ACL upgrade step.

## Delivered — 1.3.0

Review fixes from PRs #17–#21 are merged on main. The 337 unit and component
cases and the installed lifecycle gates passed on the final review revision.
This release adds restricted ACME issuance permissions, filtered Certbot
environments, service startup and HTTP-01 fixes, canonical domain validation
and per-service Vault CA configuration. See the [release notes](docs/release-notes.md)
for upgrade steps. [Release #22](https://github.com/decryptus/certlord/pull/22) shipped at tag
[v1.3.0](https://github.com/decryptus/certlord/releases/tag/v1.3.0). The downloaded
PyPI wheel and sdist match the GitHub release SHA-256 digests. Docker Hub tags
At publication, 1.3.0 and latest shared manifest
`sha256:bb3fd26d1670a49a42a56cecff76624d3727206c0c4b4c493f6ab34e0ea37a09`
for Linux amd64 and arm64. The registry description matches the tagged source.
[Website PR #25](https://github.com/decryptus/atraxis-site/pull/25) deployed
the French and English pages. Both public pages serve the versioned installation
command and migration guide.

## Implemented — experimental AWS / CloudFront connector

- Prepared a [contributor contract and read-only preflight](docs/cloudfront-qualification.md)
  for renewal of one existing imported ACM viewer certificate on one distribution.
  The tool checks explicit account/region/resource binding, domain, fingerprint,
  validity and unshared ownership; it can generate an exact-resource read policy.
- Implemented the [experimental renewal job](docs/cloudfront-renewal-job.md):
  immutable profile/selector binding, read-only Vault AppRole, existing-ARN ACM
  reimport, durable intent and process lock, uncertain-request quarantine,
  read-back and exact trusted TLS verification. Implementation is tracked in
  [PR #16](https://github.com/decryptus/certlord/pull/16); it is experimental and
  inactive by default, with no automatic daemon or Compose activation.
- Offline coverage: 13 preflight + 18 writer unit cases and five pinned-SDK
  scenarios. Installed local acceptance adds real Vault HTTPS/AppRole, Auton,
  Redis and TLS with a controlled HTTP provider. Local tests cannot certify AWS.
- Validated locally and in CI: 314 unit cases, 11 contracts, five SDK cases,
  86 installed lifecycle stages and 47 systemd stages; Python/dependency matrices,
  installed packages, Debian, amd64/arm64 Compose, Textual and captures pass.
- Integration and production qualification are separate: merging this opt-in
  experiment and releasing other CertLord work do not require an AWS account.
  Production-qualified status still requires real scoped preflight, reimport,
  observed TLS change and wrong-resource IAM denial. That evidence is pending;
  local tests do not establish AWS behavior or global propagation.
- No release or deployment is performed by this integration. Stable 1.2.0
  PyPI/Docker artifacts, Compose pins, registry descriptions, captures, demos and
  FR/EN websites remain unchanged. A later version may include the experiment
  with explicit labeling and normal delivery checks; AWS qualification does not
  freeze those releases. No immutable release is overwritten.

## Delivered — ACME acceptance reliability (post-1.2.0)

- Reproduced the HTTP-01 negative-case failure by forcing valid authorization
  reuse. Pebble 2.10.1's zero-percent setting still permits 1% reuse; a reused
  authorization bypasses the challenge expected by both fault scenarios.
  The old failure reports lack sufficient Certbot diagnostics to attribute every
  historical failure conclusively.
- Implemented deterministic reuse followed by explicit ACME authorization
  deactivation in the disposable fixture. Actual rejected/in-flight HTTP-01,
  interrupted pending work and recovery assertions remain enforced in both
  ordinary and systemd lifecycle runs.
- Added sanitized nested/rotated Certbot diagnostics and four regression cases
  covering inclusion, credential exclusion, bounded traceback locations and
  unavailable logs that must not mask the original test failure.
- Merged in [PR #14](https://github.com/decryptus/certlord/pull/14). All checks
  pass on its final revision: 283 unit cases, 11 contracts, 2 Textual cases,
  84 installed lifecycle stages and 47 installed-systemd lifecycle stages.
  Python 3.11/3.12 minimum/latest and installed-package matrices, Debian service
  acceptance, amd64/arm64 Compose, documentation captures and distribution
  inventory pass. The 19 CI-helper cases include one intentional pytest-only
  skip; the strict Sphinx build also passes locally. The final CI runs required
  no retries or disabled assertions.
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

- Production qualification of the implemented experimental AWS/CloudFront
  connector: real permissions, resource/region binding and observed propagation.
  This is a separate milestone, not a blocker for other CertLord development.
- Additional provider-specific deployment connectors, each with its own scope
  and acceptance evidence.
- External geographic monitoring where provider capabilities permit it; local
  checks do not establish that every CDN point of presence serves the same leaf.

These remain separate future capabilities; named destinations alone do not
implement cloud provisioning, remote fencing or exactly-once execution.
