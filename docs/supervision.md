# Certificate observations for supervision

CertLord supplies lifecycle facts through an authenticated collection API and
Prometheus endpoint. Configure thresholds, notifications and escalation in your
external supervision system.

## Read endpoints

- `GET /api/certificates/observations`: JSON with `schema_version: 1`, collection
  start/completion times and a `certificates` array.
- `GET /api/certificates/metrics`: Prometheus text exposition 0.0.4.

Both require the existing `read` API permission and return `Cache-Control: no-store`.
Use HTTPdis authentication and HTTPS termination for a remote reader. The existing
explicit loopback-only local authentication mode still applies; these routes do
not create another authentication mechanism. Grant the collector `read`, not
`write` or `deploy`. Do not publish these endpoints or their operational data.

Existing configurations need the two routes under `modules.ssl_certs.routes`:

```yaml
observations:
  handler: observations
  name: api/certificates/observations
  op: GET
metrics:
  handler: metrics
  name: api/certificates/metrics
  op: GET
```

## JSON facts

Each record contains server UUID, domains, Vault version, stored lifecycle status,
origin, renewal owner, pending action, current ACME issuance retry count and last
retry time, material state, leaf validity dates and SHA-256 fingerprint. Private
keys, PEM certificates/chains, backend credentials and raw exception messages are
never included. Expiry is parsed from the stored leaf for both ACME and external
certificates; cached import metadata is not the source of truth.

`material_state` is `readable`, `missing` or `invalid`. Readable means the leaf can
be parsed, not that it is trusted, currently valid or served by a destination.
Expired and not-yet-valid leaves remain observable. Missing/malformed material
has null dates/fingerprint, never an invented expiry of zero. Unknown lifecycle
values are reported as `unknown`, not copied into free-form error fields.

`issuance_retry_count` is the current Redis retry value only for pending ACME
`create` or `renew` actions. Otherwise it is null. It can reset or disappear and
is not a lifetime failure counter, an exact failure reason or a claim that the
last renewal succeeded. `last_issuance_retry_at` is UTC. Historical failure details
are not persisted by this feature. `pending_action` can also expose `invalid-dns`
or `delete`; neither is counted as an ACME renewal retry.

## Prometheus metrics

All metrics are gauges:

| Name | Meaning |
| --- | --- |
| `certlord_observation_completed_timestamp_seconds` | Completion time of this successful collection |
| `certlord_certificates_observed` | Number of records returned |
| `certlord_certificate_info` | Value 1 with UUID, origin, renewal owner, status, pending action and material state labels |
| `certlord_certificate_not_after_timestamp_seconds` | Stored leaf expiry, labelled by UUID |
| `certlord_certificate_issuance_retry_count` | Pending ACME retry count, labelled by UUID |
| `certlord_certificate_tls_verification` | Last recorded check status (`verified`, `failed`, `not_checked`), labelled by UUID |
| `certlord_certificate_tls_verified_at_timestamp_seconds` | UTC Unix time of a recorded successful TLS check |

Expiry samples are absent for missing/invalid PEM; retry samples are absent when
not applicable. Domains and certificate fingerprints are omitted from metric
labels to avoid extra label churn. Use the JSON endpoint for those details.
Collectors choose their own expiry thresholds; CertLord imposes no alert window.

## Freshness, errors and limits

Every request reads Vault and Redis without writing certificate or queue state.
A backend outage fails the request with HTTP 503; no successful partial/empty
collection or cached healthy value is substituted. A confirmed concurrent removal
is skipped. An actually empty store returns a successful zero-record collection.
The collection carries start/completion times and a per-record observation time;
Vault and Redis are separate reads, not one atomic snapshot. A storage version
identifies the Vault read only. Readers must distinguish unavailable/stale
observations from a certificate's expiry or pending status.

The endpoints read the full inventory synchronously. They are intended for the
current single-active deployment scope, not a claimed large-fleet scrape SLA.
Choose a reasonable scrape interval and timeout for the inventory size; load
and scale acceptance remains open. Failure means the whole collection failed.

Expiry and fingerprint fields describe **stored** material. The optional
`verification` field and TLS gauges describe the last recorded
[post-deployment TLS check](tls-verification.md), not continuous supervision.
The endpoints report observations and do not send notifications.
