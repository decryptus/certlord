# Operating the initial single-active deployment

This guide covers one active CertLord scheduler, one authoritative Redis backend,
Vault storage and an idempotent Auton deployment job. It does not authorize or
claim multi-active operation, cloud deployment or historical-package migration.
Use [installation](debian-installation.md), [ACME configuration](acme-connector.md)
and [TLS verification](tls-verification.md) for setup. Keep operational information
and credentials private.

## Health and current work

All four GET routes require the existing `read` permission and disable caching:

| Route | Meaning |
| --- | --- |
| `/api/health/live` | The authenticated API is responding; no backend probes |
| `/api/health/ready` | HTTP 200 only after scheduler start, while all three worker threads are alive and Vault listing/Redis ping succeed; otherwise 503 |
| `/api/operations` | Current Redis work plus local and stored worker-cycle evidence as JSON |
| `/api/operations/metrics` | The same current-work gauges as Prometheus text |

Add these handlers/names to an existing `modules.ssl_certs.routes` configuration:

```yaml
live:
  handler: live
  name: api/health/live
  op: GET
ready:
  handler: ready
  name: api/health/ready
  op: GET
operations:
  handler: operations
  name: api/operations
  op: GET
operation_metrics:
  handler: operation_metrics
  name: api/operations/metrics
  op: GET
```

Use a read-only collector account over HTTPS. For example, `curl --user reader
--max-time 15 https://certlord.example.com/api/health/ready` prompts for its
password; do not put passwords in shell history. The explicit loopback fixture
authentication mode retains its existing behavior. Liveness requires read access
also; it is not a public diagnostic route.

Readiness checks thread existence, not forward progress or all operational
permissions. A blocked but live worker can still pass this test. Vault listing
can succeed while a later write/destroy is denied. Use readiness together with
pending ages, retry state, certificate expiry, logs and dated TLS results. A
readiness failure alone should not trigger destructive cleanup or an infinite
restart loop. These probes have backend socket timeouts but no single end-to-end
server deadline across all authentication, lock and backend calls.

## Interpreting queue and retry observations

Pending action counts cover `create`, `renew`, `delete`, `invalid-dns` and `other`
in the shared certificate Redis namespace. Retry totals and counts at the retry
limit cover only create/renew/delete actions, matching the issuance worker's
retry gate. They are current values, not lifetime counters. The limit comes from
`max_retries`; observation never resets it.

Deployment counts/ages concern this configured `general.server_id`. Oldest age
uses the original enqueue timestamp, including repeated attempts of the same
material. Missing timestamps are counted explicitly; an empty/undated queue has
no invented age of zero. Lease state is `held`, `absent` or `unbounded`; its TTL
can be reported without reading or revealing the owner token. A held lease is
not proof that a local or remote deployment is still progressing.

Prometheus exposes `certlord_pending_actions{state=...}`,
`certlord_deployment_lease_state{state=...}` and the
`certlord_operations_` gauges corresponding to the numeric JSON fields.
Prometheus does not expose UUIDs, domains, key material, Redis key names or lease
tokens. JSON includes server-generated instance/cycle IDs for log correlation,
never certificate material or credentials.

`operation_scan_limit` (default 10000, under `modules.ssl_certs`) caps observed
unique pending keys and deployment members per request. Exceeding it, corrupt
state or Redis failure returns 503, not truncated success. Scans and backend
reads are not one atomic snapshot; concurrent mutation can affect observations.
This item cap is not a fleet-scale latency guarantee. Choose a modest polling
interval and monitor scrape failures; no poll repairs or mutates the queues.

## Worker cycles and restart evidence

`operations.cycles` contains the current process `instance_id`, `local` cycle
records and `stored` Redis records for the three scheduler workers. Each cycle
gets a server-generated `cycle_id`, also present in structured `cycle_progress`
log entries. These are diagnostic IDs, not certificate identities, authentication
credentials or client-selected idempotency keys.

A record is `running`, `returned`, `raised` (an exception escaped the cycle), or
`stopped` (the worker observed a stop request). **Returned does not mean successful
operations:** per-certificate failures can already have been handled internally.
Start/end times use wall time; completed duration uses a monotonic clock and
includes the start write wait, but excludes the final persistence call. A running
cycle has no fabricated completion time/duration. Compare its start time with the
current time and the expected workload; CertLord sets no stall threshold. An idle
crawler or deployer may legitimately wait hours between cycles. Readiness remains
a separate thread/backend check.

Redis retains only `current` and `previous_instance` per worker, under a hashed
server namespace. The first cycle of a new instance preserves the previous
instance's final known record; later cycles of that same instance leave it intact.
A prior `running` record means **no completion was recorded**, not proof that no
external side effect occurred. The next restart replaces this one-generation
history. Direct `_run` calls in the test harness do not represent scheduler cycles.

Redis ACLs must permit `EVAL`/`HGET`/`HSET` for recording and `HMGET` for reading
the cycle namespace. Persistence is best effort and uses the existing finite Redis socket timeouts
without automatic replay. Each cycle adds one start and, when acknowledged, one
conditional finish write. These calls add latency; a worker stopped during the
start write does not launch its callback. Failure logs omit backend exception
contents. `local.persisted=false` means the last event was not acknowledged; a
network timeout may still have applied the write. No failed write repairs queues
or cancels certificate work. A late completion cannot replace a newer cycle.
This mechanism is neither an execution lease nor multi-active fencing.

Reading unavailable/corrupt stored evidence fails the operations request with
503. Missing records remain null. Local and stored observations can race and are
not a transactional snapshot. Data survives a CertLord process restart while Redis
retains it; Redis crash durability depends on the configured AOF/RDB policy. This
is not an append-only audit trail. Retain/export logs according to local policy;
end-to-end certificate/API/Auton audit correlation remains separate work.

Prometheus adds `certlord_worker_cycle_` gauges for `running`, `persisted`,
`started_timestamp_seconds`, `finished_timestamp_seconds` and `duration_seconds`,
using only the three fixed worker labels. Missing completion values are omitted;
instance/cycle IDs are excluded from metric labels. An external supervision system owns any alerting
policy; a collector integration is not implied by exposing these facts.

## Incident and recovery sequence

1. Check API liveness, readiness and backend availability separately. Preserve
   dated observations, sanitized logs and the relevant certificate UUID/version.
2. Inspect certificate state and pending work before changing anything. A failed
   command may already have submitted an Auton job; check its result and the
   actually served certificate before replaying it.
3. Repair the cause (trust bundle, endpoint reachability, credentials, Vault
   availability or Redis availability). Allow existing worker/retry/lease logic
   to reconcile. Do not delete lease keys or flush Redis to force progress.
4. After recovery, verify pending work drains, the expected certificate is stored
   and the configured destination has a fresh successful TLS result. Clearing
   an alert without these checks is not acceptance.

A TLS verification retry currently reruns Auton. Commands must be idempotent and
must validate the remote server configuration before reloading it. Remote rollback
is adapter/job-specific and is not automatically performed by CertLord. Pause the
service for controlled maintenance if necessary. A stopped process does not cancel an already-submitted
remote job.

## Backups and restoration

Protect Vault data and metadata (including version/CAS history and reserved
identity definitions), the relevant Redis databases, configuration and deployment
job definitions. Keep credentials in a separately protected secret backup; never
commit them to Git. Use the backup mechanism supported by the actual Vault storage
backend and Redis persistence mode. Protect access, encryption and retention as
for private keys.

Before a coordinated recovery, stop all writers and account for remote jobs. A
Vault-only or Redis-only rollback can recreate stale associations, callbacks or
queue entries. Restore into an isolated environment first, preserving UUIDs and
Vault version history; compare material, pending work and served destinations
before allowing production writes. Do not assume snapshots from two independent
stores are transactional. Backup restoration drills and production RPO/RTO remain
operator acceptance gates, not evidence supplied by the test suite.

## Credential rotation

Rotate API, Vault and Auton credentials independently. For AppRole, provision the
replacement credential with the intended policy, install it through the protected
configuration mechanism, restart the service and verify authorized reads/writes
and deployment in staging before revoking the previous credential. Prefer short
lived, narrowly scoped credentials where supported. Never expose a Vault token as
an API credential. Existing CI tests cover scoped AppRole access, token expiry and
explicit Secret ID replacement in a disposable environment; they do not constitute
a live rotation or a universal rollout recipe.

## Supported operating scope

Use one active lifecycle daemon, one authoritative Redis and idempotent Auton
jobs. Validate backup/restore and credential rotation on your own deployment.
Readiness does not certify production safety or durable remote-job recovery.

## HTTP error contracts

Application validation errors return JSON HTTP 400 (invalid domain/UUID, request
shape or challenge payload). The former 415 responses on these handlers were
incorrect: 415 denotes an unsupported media type, not invalid field values.
Clients should classify 400 as a request correction, not retry it unchanged.
Authentication remains owned by HTTPdis (401); denied operation permissions use
403. Missing certificate resources and absent ACME challenges use 404, version/
state conflicts use 409, and busy/unavailable services use 503. Readiness retains
its documented JSON health body and 503 when not ready. Framework parsing, route
selection and unsupported-method behavior are separate contracts.

An absent challenge no longer returns empty HTTP 200. A Redis read failure is
still 503 and must not be interpreted as absence. Successful and absent public challenge
reads carry `Cache-Control: no-store`; cleanup of an already absent challenge
remains idempotent. Challenge token/payload validation rejects trailing newlines
before storage access. Operational metric formatting exceptions use the same
sanitized 503 boundary as the underlying observation.

## Worker log confidentiality

Certlord does not copy Certbot arguments, stdout/stderr or caught worker
exception text/tracebacks into its own logs. Fixed failure messages and command
exit codes preserve basic diagnosis, with existing worker-cycle records for
context. Retry and pending state remain authoritative; a returned cycle is not
proof of successful issuance or deployment. Certbot's own log files are separate
and must be protected; this policy does not sanitize them. See [operation correlation](operation-correlation.md) for diagnostic events and
optional confirmed Auton receipts.

## Following a certificate operation

Authenticated certificate detail and inventory include `operation_id` for new
records. This non-secret server-generated UUID follows accepted management work
through stored issuance and deployment state. Search `operation_progress` logs
for the same value; deployment command events also carry a local `attempt_id`.
A returned command is not an acknowledged deployment. Existing records may omit
this field, and automatic renewals retain the initiating operation lineage.
See [operation correlation](operation-correlation.md) for semantics and limits,
including opt-in confirmed Auton job receipts and the still-open retained
removal/history audit.
