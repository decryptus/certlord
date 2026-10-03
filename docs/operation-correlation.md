# Operation correlation

Certlord adds a non-secret `operation_id` to newly created certificate records
and exposes it in authenticated certificate detail/inventory metadata. It is a
server-generated UUID4, distinct from the certificate UUID, canonical SHA-256
identity, issuance callback credential and deployment lease token. Clients cannot
choose it or use it for authorization, deduplication or replay acceptance.

Creation and external import persist the ID with the first record. Replaying the
same creation/import preserves the stored ID. External material replacement gets
a new ID in the same conditional write as the replacement. Requested removal or
restoration attaches the request's ID when it updates certificate state. A no-op
update does not manufacture a new stored operation. Old records without this
metadata remain usable and are not silently backfilled by reads.

An automatic ACME renewal retains the initiating management operation ID. The
issuance callback and deployment writes preserve it across worker/API restarts.
It identifies a management operation lineage, not a unique renewal attempt or
certificate generation. Certificate versions and existing generation checks remain
authoritative for concurrency; operation IDs never replace them.

## Structured diagnostic events

The `certlord.services.operation_tracking` logger emits `operation_progress`
followed by a JSON object containing an event and operation ID, optionally a
validated certificate UUID and attempt UUID. No bodies, domains, private keys,
callback/lease tokens, command arguments, output or exception messages enter
these records. Existing logger configuration controls delivery and retention.
A logger failure does not fail or roll back certificate work.

Service events use `*_started`, `*_returned` and `*_raised`. Returned only means
the synchronous call returned. An idempotent replay can return a previously
stored operation; `existing_operation_returned` links that stored ID to the new
request attempt. Storage events are emitted only after the corresponding call
returns. An ambiguous backend error can follow a committed write without a
storage event; missing logs are not proof of missing mutation.

Each local deployment command receives a fresh attempt UUID. Events associate
all selected certificate operations with that shared attempt. They distinguish
started, uncertain command failure, unacknowledged exit/interruption, returned
command and acknowledged deployment. A zero command exit is not acknowledgement:
`deployment_acknowledged` follows the existing certificate update and lease-owned
queue acknowledgement. Configured TLS verification must still pass first.

## Limits and remaining work

In default command mode, the attempt UUID is **not a confirmed Auton job ID**.
The opt-in receipt mode below confirms the existing Auton single-job protocol
identity; arbitrary command output is never interpreted as a receipt in default
mode.

The persisted field records the latest management operation associated with a
certificate, not a complete history. Removal destroys certificate history under
the existing policy; this change adds no retained removal audit. Logs are not an
append-only audit database, and individual events/attempt IDs are not guaranteed
to survive a host crash. Authentication denials and parse failures before the
service boundary are outside this scope. There is no new API operation endpoint,
new credential, new distributed lock or exactly-once guarantee.


## Confirmed Auton receipts (opt-in)

Set `modules.ssl_certs.auton.receipt_mode: true` to use the structured single-job
`auton --mode run/status` contract (tested with Auton 1.2.1). Default `false`
retains the existing configurable command behavior. This mode accepts one plain
HTTP(S) origin without embedded credentials/path/query and one endpoint; only
`--http-timeout` and `--delay` overrides are supported in `auton.args`. Existing
separate credential environment, PATH and become settings remain in use. The
worker polls every second; CLI `--delay` does not control this explicit polling.

The local attempt UUID is proposed as the job ID using Auton's existing protocol.
It becomes an observed remote job only when a JSON response returns the exact
expected endpoint/ID and a valid status. Submission happens once; subsequent
commands only read that same job's status. Read failure, invalid JSON, mismatched
identity, timeout or interruption does not trigger submission inside the attempt.
The total polling budget uses the command timeout, plus existing subprocess
cleanup grace. No raw output/error/credentials are logged or retained as receipts.

`auton_job_observed` events link `remote_job` to certificate operation and local
attempt IDs. Observation alone does not acknowledge deployment. A complete result
must report successful return, without uncertain/cancelled/interrupted outcome;
existing version/lease checks and optional TLS verification still apply.
`deployment_receipt` is stored in Vault in the same conditional write that marks
the certificate deployed, containing only origin, endpoint, UID, status and return
code. New imported material and copied certificate associations discard obsolete
receipts; ACME save replaces the material record. A receipt is not exposed as an
API credential or used to authorize operations.

This closes the remote identity link for successful deployments in receipt mode.
Failed/interrupted jobs may only have diagnostic events; their receipts are not
persistently reconciled after a host crash. Existing lease-expiry retry policy
remains, and a later attempt can submit a new job. This is not exactly-once remote
execution, remote cancellation, durable failed-job recovery or a complete audit
history. The operator remains responsible for idempotent deployment jobs. Default
command mode cannot claim a confirmed remote-job receipt.


