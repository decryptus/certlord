# Named deployment destinations

Starting with 1.1.0, a certificate can have 1–32 named destinations. Each has an
explicit Auton credential profile and a TLS endpoint. All configured destinations
are required: the certificate remains `generated` until every destination serves
the expected leaf over a trusted TLS connection. The detail and inventory APIs
expose partial results in `deployment`; `generated` does not mean that nothing
has changed remotely.

## Configure a certificate

Obtain its UUID with `certlord show DOMAIN --json`. Add profiles to the existing
private credential file; keep it readable only by the service account. These
are illustrative addresses and credentials, not working endpoints:

```yaml
auton-west:
  uri: https://auton-west.example.org
  endpoint: deploy-certificate
  auth-user: certlord
  auth-passwd: REPLACE_WITH_A_SECRET
auton-east:
  uri: https://auton-east.example.org
  endpoint: deploy-certificate
  auth-user: certlord
  auth-passwd: REPLACE_WITH_A_SECRET
```

Under `modules.ssl_certs`, configure:

```yaml
deployment_destinations:
  12345678-1111-4111-8111-111111111111:
    west:
      credentials: auton-west
      tls: {host: 192.0.2.10, port: 443}
    east:
      credentials: auton-east
      tls: {host: 192.0.2.11, port: 443}
      # A private CA can be specified inside tls as an absolute ca_file path.
tls_verification:
  timeout: 10
  targets: {}
```

Names start with a lowercase letter and contain up to 64 lowercase letters,
digits, underscores or hyphens. Profiles require explicit URI, endpoint, username
and password; ambient Auton credentials are not used for named destinations.
Remote Auton endpoints require HTTPS; plain HTTP is accepted only on loopback.
Keep the existing default `auton` credential profile for certificates using the
legacy global deployment. Never combine a named plan and a legacy TLS target for
the same UUID. Restart CertLord to apply configuration, then request its existing
deployment/crawl cycle (`POST /api/ssl-certs/deploy`, requiring `deploy`).

Adding a destination or changing its Auton origin/endpoint, TLS endpoint or CA
bundle invalidates that destination's prior success. Unchanged destinations keep
their evidence for the same material. New PEM material or an ACME renewal
invalidates all previous destination results. Removing a configured destination
does not remove its installed certificate or cancel its old jobs.

## Auton job contract

Each destination uses the structured Auton run/status protocol and the configured
command deadline. `auton.args` may contain only `--http-timeout` and `--delay`
overrides; the existing explicit `search_paths` and `become` settings are retained.
Use Auton 1.2.1 or later. CertLord appends four positional job arguments, in order:

1. Certificate UUID.
2. Bound certificate domain.
3. Certificate generation: SHA-256 of the compact JSON array `[cert, chain]`,
   using the exact stored PEM strings and UTF-8 encoding.
4. Destination name.

Configure a dedicated, idempotent Auton endpoint that accepts these arguments.
It must validate its allowed certificate/destination, securely fetch material
using its own narrowly scoped credentials, and reject a superseded generation
before installing. Private keys and certificate contents are never passed as
command arguments. Do not point this configuration at an old global hook that
ignores the selectors and deploys every certificate.

CertLord persists the attempt UUID in Vault **before** submitting the job. On
restart or an uncertain response, it queries that same job's status; it never
infers that a missing job is safe to resubmit. The endpoint should retain job
results long enough for recovery. A missing/expired result remains uncertain.
This protocol cannot guarantee exactly-once remote effects or fence a job already
running on another host; the deployment endpoint owns idempotency and remote
generation protection.

## Results and targeted retry

```sh
certlord show www.example.org --json
certlord retry-destination www.example.org east --expected-version 17 --json
```

Read the current `version` immediately before retrying; it is the Vault record
version, not the certificate generation. A stale version returns a conflict.
The authenticated API equivalent, requiring `deploy`, is:

```text
POST /api/certificates/UUID/destinations/east/retry
{"expected_version": 17}
```

The call resets only the chosen failed destination and requests a crawl. It does
not wait for completion. Successful destinations cannot be retried by this call.
An uncertain/submitting destination additionally requires
`--acknowledge-uncertain` (API: `"acknowledge_uncertain": true`): its previous
remote job may still execute, so a new attempt relies on the endpoint's
idempotency. No retry is triggered by reading the CLI/TUI or API details.

Destination states are `pending`, `submitting`, `uncertain`, `verifying`, `failed`
and `verified`. The aggregate shows `partial` when some destinations are verified
and others are not. A command with a confirmed failure waits for explicit retry.
When the command succeeded but TLS did not verify, later worker cycles only
repeat the TLS check. An explicit retry can instead request a new deployment of
that failed destination. Existing worker intervals apply; no automatic rollback,
new backoff schedule or continuous TLS monitoring is introduced.

The detail/inventory `deployment` object includes generation, expected leaf
fingerprint, verified/total counts, destination names, attempt IDs and sanitized
TLS results. CLI `show`, curses details and Textual details display this evidence.
Credentials, peer errors, PEM data and private infrastructure addresses are not
returned. The observation/Prometheus schema remains compatible: its singular
`verification` fields describe the legacy single target; use the detail/inventory
API for named destination results.

## Upgrade and verification limits

Existing configurations keep the global command and single-target TLS behavior.
Opting a certificate into a named plan starts with no named-destination evidence,
even if the old global status was deployed. It runs the named jobs once before
acknowledgement. No storage conversion or data deletion is required.

Vault conditional writes reject results captured before replacement or removal.
Redis retains the existing generation-specific queue and deployment lease. The
write and queue acknowledgement are not one transaction; recovery preserves
verified destinations and repairs acknowledgement without redeploying them.

Tests use disposable certificates and local TLS listeners. Integrated acceptance
uses the actual installed CertLord, Auton, Vault and Redis, including a partial
failure, process restart, targeted retry and replacement on all three endpoints.
This is not a public-CA, production-host, multi-CDN propagation or geographic test.
