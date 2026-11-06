# CertLord 1.3.2

New installations use **127.0.0.1:8667**, distinct from Auton on port 8666.
The CLI default, Certbot connector examples, Docker listener, challenge proxy
and authenticated readiness probe use the same new port.

## Upgrading from 1.3.1

Existing configuration files are not rewritten. Coordinate the listener, connector,
clients, reverse proxy and monitoring URLs before restarting. For Compose, migrate
the mounted configuration to 8667 and use the matching 1.3.2 image and Compose file.
`CERTLORD_PORT` changes only the loopback host port. To keep a native listener on
8666, explicitly set `CERTLORD_API_URL` or `--url`. Do not change the Auton URI.
See [port migration](../MIGRATION.md#certlord-api-port); let active challenges finish
and preserve credentials and persistent data.

Health routes intentionally remain authenticated. Use a dedicated read-only
account and mounted probe secrets; see [orchestrator probes](operations.md#orchestrator-probe-authentication).
Real AWS/CloudFront qualification remains pending. Publication does not upgrade
existing services automatically.

Install `certlord==1.3.2` or `decryptus/certlord:1.3.2` after publication.

# CertLord 1.3.1

The issuance worker now scans pending Redis certificates in batches. Each key is
processed at most once per cycle, and cleanup preserves entries replenished by
another writer. The stored keys and certificate format stay compatible.

## Upgrading from 1.3.0

- If you restrict Redis commands with ACLs, grant the worker `SCAN` before
  restarting CertLord. Keep its existing read, write and script permissions.
- CertLord now requires HTTPdis 0.6.39 or later for request parsing, handling
  of Basic credentials and HTTP error details. For a browser frontend hosted
  on another origin, configure the trusted origin at your reverse proxy.
- The minimum Sonicprobe version is 0.3.63, which stages temporary file
  replacements on the destination filesystem. This raises the effective minimum
  pyOpenSSL version to 26.4.0.

Install `certlord==1.3.1` or pull `decryptus/certlord:1.3.1`.
See the [migration guide](../MIGRATION.md) before restarting the active daemon.

## CertLord 1.3.0

ACME callbacks now accept ECDSA keys and validate the certificate, key, DNS name,
validity dates and supplied chain before writing to Vault. An identical callback
can be retried after deployment. Certificate routes use the same domain identity
for case, IDNA labels and a trailing DNS root dot.

## Upgrading from 1.2.0

- Check Certbot DNS plugins and hooks before restarting. Set
  `modules.ssl_certs.certbot.pass_env` to the extra environment variable names
  they need. Existing installations with root-owned Certbot accounts and
  lineages should follow the [migration guide](../MIGRATION.md) before
  switching to the service account used by the new Debian example.
- After upgrading every daemon, replace the ACME connector's `write` permission
  with `issue` and retain `challenge`. Existing writers can still save
  certificates. See the [connector guide](acme-connector.md).
- Let active HTTP-01 challenges finish before the upgrade, or republish any
  challenge originally submitted with a trailing slash.
- The Debian example listens on `127.0.0.1:8666`. A daemon launched as root
  resets supplementary groups before changing identity. Startup failures return
  a nonzero status to the supervisor.
- Vault HTTPS supports a dedicated `credentials.vault.ca_bundle` and the
  existing `VAULT_CACERT` environment setting. See the [Vault guide](vault-approle.md).

The optional CloudFront job can renew an existing imported ACM certificate.
It is disabled by default. Its integration tests use a controlled provider.
Qualification against live AWS permissions and actual edge propagation is pending.

## CertLord 1.2.0

Independent TLS monitoring checks up to 32 configured web servers, reverse proxies,
load balancers or CDN endpoints, without issuing or deploying a certificate.
The connection address and TLS name are explicit. Trust, dates and hostname are
always validated; an optional SHA-256 pin requires a specific leaf certificate.

A bounded worker persists observations in Redis. Missing, failed and stale results
remain distinct; only fresh successful checks count as verified. Read observations
through the REST API, CLI, curses, Textual or Prometheus-format metrics. An explicit
write-authorized request wakes the worker; read requests never launch probes.

See [independent TLS monitoring](tls-endpoints.md) for configuration, API routes,
upgrade steps, pin rotation and the limits of a single observation location.
Existing CertLord service dependencies and the single active daemon requirement
remain in place. The feature is disabled by default.

Install `certlord==1.2.0` or `decryptus/certlord:1.2.0` once published.

## CertLord 1.1.0

Named deployment destinations add per-server Auton jobs, exact leaf TLS checks,
persistent progress and partial-failure reporting. Successful destinations are
preserved on retry; an interrupted submission resumes the same remote job's
status. A failed target can be retried with an exact record version. Uncertain
jobs require explicit acknowledgement before requesting a new attempt.

Configuration is opt-in. Existing global command and single-target TLS behavior
remain supported. New material invalidates all old target results. See
[named destinations](multi-destination.md) for configuration, the required
idempotent job contract, migration and recovery limits.

Install `certlord==1.1.0` or use `decryptus/certlord:1.1.0` after publication.
Preserve configuration, Vault/Redis data and credentials and restart deliberately.
No existing server is upgraded automatically.

## CertLord 1.0.1

This maintenance release bounds combined command stdout/stderr to 4 MiB and
raises an explicit failure when output exceeds that budget. Truncated command
output is never accepted as a successful receipt. Cleanup also bounds discarded
output so a noisy child cannot extend termination indefinitely.

Process selector initialization now occurs before launch. Launch or pipe
registration failures close owned resources and terminate/reap a started child.
The existing deployment retry policy remains unchanged: remote jobs still need
idempotent behavior, and local process cleanup does not prove a remote effect
was cancelled.

Install with `python -m pip install --upgrade 'certlord==1.0.1'`, or use
`decryptus/certlord:1.0.1` with the current Compose guide.

## CertLord 1.0.0

First stable release — 8 October 2026. Promotes the qualified rc2 feature set
without adding runtime features. The supported topology uses one active lifecycle
daemon; the operating limits below remain part of the release contract.

## Included

- ACME HTTP-01 issuance and renewal through Certbot and ACME HTTP Connector.
- External PEM import with certificate/key checks and explicit versioned replacement.
- Vault KV v2 storage and separate API/Vault authentication responsibilities.
- Authenticated HTTP administration, CLI commands and an explicitly selected TUI.
- Redis work tracking, deployment leases, retries and bounded worker shutdown.
- Auton deployment, optional confirmed remote receipts and destination TLS checks.
- Authenticated certificate/worker observations and Prometheus metrics.
- Optional read-only Textual browser: install `certlord[textual]` and run
  `certlord tui --ui textual`.

## Installation and supported scope

Python 3.11/3.12 on POSIX; Debian packaging targets Debian 12 / amd64. Provision
Vault, Redis and Auton separately. Use one active lifecycle daemon and idempotent
deployment jobs. See [installation](https://github.com/decryptus/certlord/blob/v1.0.0/docs/debian-installation.md),
[configuration and operations](https://github.com/decryptus/certlord/blob/v1.0.0/docs/operations.md) and [installation evaluation](https://github.com/decryptus/certlord/blob/v1.0.0/docs/rc-evaluation.md).

Install the exact stable version:

```sh
python -m pip install 'certlord==1.0.0'
```

## Limits

There is no exactly-once remote execution guarantee. A remote job can survive a
local timeout or expired lease, and a later attempt can resubmit work. Confirmed
receipts do not provide durable recovery of every uncertain job. Optional TLS
verification covers one configured destination per certificate.

Rehearse backup restoration, credential rotation and uncertain-job recovery on
your deployment. Disposable CI does not establish production readiness, saturation
capacity or long-duration stability. Live monitoring providers and additional
platforms require separate qualification. No automatic production deployment is
performed by publishing this release.
