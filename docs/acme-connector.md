# ACME HTTP Connector integration

CertLord keeps Certbot as the ACME client. The `certbot-httpreq` adapter uses
`acme-http-connector` for HTTP challenge publication, cleanup and certificate
callbacks. The existing plugin names remain `certbot-httpreq:auth` and
`certbot-httpreq:installer`; the core alone does not replace the Certbot plugin.

The current lifecycle check uses adapter 0.0.24, core 0.2.1 and Certbot 5.8.0.
CertLord now requires adapter 0.0.24 or newer. This tested combination is not a
compatibility claim for every dependency version allowed by inherited metadata.

## Separate plugin configuration

Copy `etc/certlord/certbot-httpreq.yml.example` to
`/etc/letsencrypt/certbot-httpreq.yml`, owned by the account running Certbot and
readable only by that account (mode 0600). This example assumes both processes
run on the same host and CertLord listens on port 8666. Bind the example
CertLord service to loopback before using these unauthenticated local URLs.
It is not a production exposure policy.

For another location, pass both `--certbot-httpreq:auth-config` and
`--certbot-httpreq:installer-config` in the configured Certbot argument list.
An explicit `modules.ssl_certs.certbot.args` replaces the entire default list;
retain the authenticator, installer, non-interactive flags and `run` subcommand.
Do not rely on environment-only configuration when using `search_paths`: the
existing command builder supplies a PATH-only environment in that mode.

## Route contracts

| Phase | Request | CertLord behavior |
| --- | --- | --- |
| Publish | PUT `/.well-known/acme-challenge/<token>`, JSON string containing key authorization | Stores validation with an atomic expiry under the request path in the challenge Redis database. |
| Read | GET the same path | Returns validation for the ACME server and adapter self-check. |
| Cleanup | DELETE the same path | Removes the challenge Redis key. |
| Save | POST `/api/ssl-certs/save`, JSON domain/cert/key/chain and `X-CertLord-Issuance` header | Requires the current persisted attempt identity before conditional storage writes. |

Leave `param_challenge` and `param_validation` unset. CertLord expects the token
in the route and a JSON string body, not a nested validation object. Leave the
deployment field names unchanged. Certificate callbacks include the private key.

`modules.letsencrypt.challenge_ttl` is a positive integer number of seconds,
default 3600 (maximum 2147483647). Publication uses Redis SETEX so a client crash
or unavailable cleanup endpoint cannot leave a newly published challenge forever.
Normal DELETE still removes it immediately; publishing the same path renews its
expiry. Set the TTL above the longest expected ACME validation/command duration.
This bounds retention, not immediate revocation on interruption. Existing keys
written without an expiry are not migrated or deleted automatically.

The requested domain must resolve to a controlled HTTP-01 frontend on port 80.
Forward public challenge GET requests to CertLord, preserving the path. The
local write URL is not enough: the ACME server checks the requested domain.
Expose only public challenge reads. Protect PUT/DELETE and certificate mutation
routes; use authenticated HTTPS for remote callbacks, with TLS verification
kept enabled. Do not expose the loopback example as a public administration API.

## Acceptance still required

Use disposable Redis databases, Vault KV v2, an isolated Auton job and a test CA.
Create a certificate/domain request through the normal CertLord API before issuance;
the save callback is part of that pending lifecycle, not arbitrary certificate
storage. Observe publish/read/cleanup and persistence, then deployment.

Verify the certificate at the actual TLS listener: SAN, issuer/trust chain,
expiry, fingerprint and key match. Renew and require a new certificate to be
served after deployment. A successful callback or Auton exit code alone is not
proof that the listener serves it. Inject issuance, Redis, Vault and deployment
failures, and check that pending work survives without false success.

No real issuance, live Redis/Vault/Auton or TLS listener was exercised by the
component tests. Those component-only results are historical; current lifecycle evidence,
including subprocess deadlines and shutdown, is recorded in [testing](testing.md).

## Lifecycle acceptance

The `Lifecycle acceptance` workflow exercises installed packages with
real loopback HTTP, disposable Redis and Vault, Pebble 2.10.1 HTTP-01 validation,
Certbot 5.8.0 and Auton 1.2.0. The Vault helper connects directly to Vault; no additional storage service is
introduced.

The harness explicitly runs production worker cycles in bounded subprocesses.
It checks issuance, Vault persistence, an Auton job failure with pending work
retained, recovery, trusted TLS with the issued certificate actually served,
renewal with a distinct serial, rejected HTTP-01 with cleanup and retained retry
state, and a real Redis outage. It uses RSA 2048 because the inherited save
schema's key-length bound does not cover modern short EC keys.

All listeners bind to loopback; names use `.test`; no production configuration
or credentials are read. Only a JSON summary containing versions, completed
checks and limits is retained for seven days. Private keys, generated credentials
and raw daemon logs remain in the temporary fixture directory and are removed.

This explicit script has its own CI job; it is not silently included in the
unit discovery count. A passing run does not validate concurrent scheduling,
worker shutdown deadlines, sustained load, external DNS policy, ECDSA or
transactional acknowledgement across Vault and Redis. Failure of any required
check fails the job and leaves the full lifecycle unvalidated.


## Managed issuance callback migration

Save callbacks now require the `X-CertLord-Issuance` header bound by CertLord before
launching Certbot. Old callbacks without it return HTTP 409. Roll out the worker
and API together with old workers stopped; do not mix versions. Existing material
remains readable, but unfinished legacy issuance must be retried by the new worker.
This endpoint is not an external certificate-import API.

The CertLord account must read the base installer YAML. A temporary copy (0600,
inside a 0700 directory) supplies the per-attempt header; run Certbot as that account
or root. Do not relax directory/file permissions to support another become user.
Normal shutdown cleans these copies, but SIGKILL/host failure can leave them behind;
clean only confirmed inactive `certlord-issuance-*` temporary directories through
the host's private temporary-file policy. They can contain copied API credentials.
Independent `certbot renew` must not reuse persisted temporary installer paths:
issuance/retry is driven by CertLord's managed worker.

Keep one active lifecycle daemon per Redis/Vault state scope. Atomic membership
updates and deployment leases do not coordinate all issuer/deletion pending state.
