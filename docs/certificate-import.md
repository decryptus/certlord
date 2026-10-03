# Import an externally issued certificate

CertLord can import an existing TLS certificate, its unencrypted private key and
an optional PEM chain through the API or non-interactive CLI. Material is stored
through the configured certificate store (currently Vault), then picked up by the
existing crawler and Auton deployment path. The API response contains metadata,
never the private key or PEM material. Command success means storage succeeded;
use the deployment status and verify the target TLS listener separately.

## CLI

```sh
certlord import www.example.com \
  --cert-file certificate.pem \
  --key-file private-key.pem \
  --chain-file intermediates.pem \
  --url https://certlord.example.com --json
```

`--chain-file` is optional. Use protected files for the private key; key contents
are never command-line arguments. The CLI uses the existing verified-TLS client
and `CERTLORD_API_USER` / `CERTLORD_API_PASSWORD` authentication. Remote HTTP and
redirects are refused. It does not enter the TUI or start a local daemon.

## API

`POST /api/certificates/import` requires the `write` operation permission and a
JSON object containing only these fields:

| Field | Value |
| --- | --- |
| `domain` | One DNS name; canonicalized like managed certificate identities |
| `cert` | One PEM leaf certificate, up to 64 KiB |
| `key` | One unencrypted PEM RSA/EC private key, up to 64 KiB |
| `chain` | Optional PEM issuer chain in leaf-to-root order, up to 256 KiB / 8 certificates |

The UUID is generated and reserved by the server using the existing canonical
identity index. Clients cannot choose it. Successful responses include
`certificate_id`, `domains`, `status`, `origin: external`,
`renewal_owner: external`, `fingerprint_sha256`, `not_after` and the current
storage `version`.

An identical import reuses its UUID and material without incrementing the Vault
record version; it can repair the reverse index after a partial Redis failure.
A different certificate, key or chain for the same identity returns HTTP 409.
An existing ACME identity or a removed identity is not converted or resurrected.
Concurrent first material writes use Vault CAS=0; a conflict is reported without
an unconditional overwrite. The Vault write and Redis update are not one atomic
transaction: an HTTP failure can follow successful storage, and identical replay
is the reconciliation path.

## Acceptance policy

The initial scope is one exact DNS SAN, matching the normalized requested name.
Multiple SANs, wildcards and IP SANs are not supported in this import version.
The leaf must be currently valid, match the supplied private key, and not be a CA.
RSA keys must be at least 2048 bits; EC keys at least 256 bits. An EKU extension,
when present, must permit TLS server authentication. Encrypted keys, extra PEM
objects/trailing data, expired/not-yet-valid material and unknown JSON fields are
rejected with HTTP 400 before storage is accessed.

Supplied issuers must be currently valid CAs, have compatible path lengths and
keyCertSign usage when present, and directly verify the preceding certificate's
signature. Duplicate or unrelated chain members are refused. PEM material is
normalized before storage/replay comparison; the displayed SHA-256 fingerprint
is over the DER leaf certificate.

This is **material and supplied-chain consistency validation**, not full PKIX trust
validation. No public/system trust anchor, revocation, complete policy/name-
constraint processing or destination-specific TLS compatibility is certified.
An omitted chain is accepted; supply intermediates needed by the destination.
CAA/DNS issuance policy is not applied to a certificate already issued elsewhere.
The authenticated importer is responsible for selecting an authorized issuer;
verify served TLS with the intended client trust store after deployment.

## Renewal and replacement

Imported records use `vendor: external`, `origin: external` and
`renewal_owner: external`. They are deployed through the existing queue but never
scheduled for ACME renewal. The issuance boundary also rejects attempts targeting
an imported record. Inventory exposes expiry metadata; configure expiry alerts in your supervision system.
Use the explicit replacement operation below to update material. A changed POST
import is still refused. Existing ACME records retain their current behavior and
are not migrated.


## Explicit replacement

First read the current metadata and its storage version:

```sh
certlord show www.example.com --url https://certlord.example.com --json
certlord replace www.example.com --expected-version 7 \
  --cert-file replacement.pem --key-file replacement-key.pem \
  --chain-file replacement-chain.pem \
  --url https://certlord.example.com --json
```

Replace `7` with the version you actually reviewed. The selector may also be the
full UUID or an unambiguous UUID prefix. The CLI never substitutes a newer version
for the supplied value. Selector lookup needs `read` permission as well as the
`write` permission required for replacement. The ordinary `show` output also
displays the version.
The version changes with storage updates, including deployment acknowledgement;
it is not just a certificate-generation number.

The API is `PUT /api/certificates/<UUID>/material`, authorized by `write`. Its
JSON accepts exactly `expected_version` (required positive integer), `cert`, `key`
and optional `chain`. Omitting the chain stores an empty chain for the new material.
The UUID in the path identifies an existing external record;
the server derives its immutable domain. A request cannot choose a new identity,
change its domain, convert an ACME record or restore a pending/completed deletion.
The import validation and trust policy above applies to the replacement material.

The version must match the snapshot being replaced. Vault performs a conditional
write against that version, so a change after validation also prevents overwrite.
Missing/malformed preconditions return HTTP 400; stale versions, incompatible
origin or pending removal return 409; absent/fully removed identities return 404.
Local simultaneous operations can temporarily receive 503 (busy).

An accepted replacement preserves UUID and identity metadata, keeps external
renewal ownership, and creates a new stored version in `generated` state for the
existing deployment queue. This also applies if explicitly replacing with the
same material. Reusing the consumed expected version returns 409; the CLI does
not automatically retry. After an uncertain response, read current metadata and
compare the fingerprint/version before deciding whether another operation is
needed. A leaf fingerprint alone does not identify chain-only changes or prove
which concurrent request committed; reconcile uncertain outcomes before retrying.
An error can follow a committed storage write.

The previously served certificate remains until the deployment changes the remote
endpoint. A failed job retains pending work for retry. Replacement does not
explicitly destroy earlier Vault versions; retention still follows the configured
Vault policy. This is not automatic remote rollback, remote
job cancellation, fencing, or proof of production TLS verification. An already
running external job can outlive the local operation. Stale deployment acknowledgement
cannot overwrite the replacement's newer storage version. The acceptance fixture
fails the remote job before it installs material; a partial remote change before
failure can still require separate reconciliation.
