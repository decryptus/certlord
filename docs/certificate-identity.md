# Certificate identities and command-line access

Each managed certificate has a stable `certificate_id` UUID. CertLord generates a
UUID4 for a new identity and retains it through issuance, deployment and renewal.
Repeated creation with the same normalized domains returns the existing UUID.
The domain is the human-facing reference; no additional display name is required. The current issuer supports exactly
one domain per certificate; multi-SAN issuance is not implemented.

An existing UUID cannot be assigned to a different domain, including after
managed removal: Vault retains its path metadata. Pre-existing duplicate certificate IDs can refer to the same domain; a domain
selector is then ambiguous and creation requires explicit reconciliation when
building a missing identity index. New POST creations reuse the existing identity. This is not organization isolation or an authorization boundary.

## HTTP API

| Request | Result |
| --- | --- |
| POST `/api/certificates`, `{"domains":["www.example.org"]}` | Creates a server-generated UUID, or returns the existing identity. |
| GET `/api/certificates` | Lists UUID, domains and lifecycle status; never certificate/private-key material. |
| GET `/api/certificates/<uuid>` | Returns one summary; 404 after completed removal. |
| PUT `/api/certificates/<uuid>`, `{"domains":["www.example.org"]}` | Reconciles/restores an existing UUID and its immutable domain; unknown UUIDs return 404. |
| DELETE `/api/certificates/<uuid>` | Requests asynchronous managed-store removal; repeatable. |

Canonical lowercase UUIDs are required in resource routes. The client never supplies
a new UUID: POST owns creation. Retrying identical creation reuses its durable
reservation, including after an uncertain response; it does not silently replace
certificate material. A busy certificate can return 503 and be retried. Pending
or completed removal returns 409 on creation. PUT explicitly restores the same
known domain after removal; it cannot change that domain. Conflicting assignments
return 409. Removal does not revoke the certificate or uninstall it remotely.

Read routes require `read`; mutation routes require `write`. Existing ACME
challenge routes and `/api/ssl-certs/save`, `/deploy`, `/validate/<domain>` retain
their contracts. Save still requires a current issuance attempt header.

## CLI

The daemon invocation and its flags remain available. Client commands are
explicit and execute before daemon initialization:

```sh
export CERTLORD_API_URL=https://certlord.example.org
certlord create www.example.org --json
certlord list
certlord list --full-id
certlord list --json
certlord show www.example.org --json
certlord show 12345678 --json
certlord remove 12345678-1111-4111-8111-111111111111 --json
```

`show` and `remove` accept a full UUID, an exact domain (case-insensitive), or an
unambiguous UUID prefix of at least eight characters. Ambiguous selectors fail
without selecting a first result. Text lists shorten UUIDs and extend prefixes
until unique within the displayed inventory. JSON always retains complete IDs;
use full IDs in durable scripts because prefix/domain uniqueness can change.

Set `CERTLORD_API_USER` and `CERTLORD_API_PASSWORD` together for HTTPdis Basic
authentication. Supply credentials through your protected execution environment,
not command arguments. These API credentials are independent of Vault credentials.
TLS verification is always enabled; `CERTLORD_API_CA` or `--ca` selects a CA bundle.
HTTP is permitted only for loopback endpoints. The default URL is
`http://127.0.0.1:8666`. `--url` overrides it; `--timeout` sets the positive finite
connect/read timeout (default 10 seconds, not a whole-command deadline).
Redirects, implicit netrc credentials and environment proxies are not used.

Commands never prompt or enter curses. Exit codes: 0 success, 1 client/selection
failure, 2 argument error, 130 interruption. Errors go to stderr, data to stdout.

## Explicit TUI

Run `certlord tui` from an interactive terminal. The read-only list shows domains,
status and short UUIDs; Enter opens details with the full UUID. Arrow keys select,
`r` refreshes and `q` exits. The TUI uses DWho terminal helpers and curses, loaded
only after the terminal check. In cron or redirected execution, `certlord tui`
fails immediately. Ordinary commands never fall back to the TUI.

## Stored identity

Vault paths use `<key_name>/<certificate_id>/<domain>`. Pending and deployment
records contain `certificate_id`; the domain reverse index contains
`certificate_ids`. Redis key prefixes are `cert:`, `domain:` and `deploy:`.
Full UUIDs are retained throughout storage and transport.


The internal fingerprint is SHA-256 of versioned canonical JSON:
`{"domains":["www.example.org"],"version":1}`. Domains are lowercased, represented
as ASCII DNS labels, stripped of a terminal root dot, deduplicated and sorted.
The HTTP endpoint still applies its existing domain schema and supports one distinct
domain. This hash is not the UUID, a secret, an authentication token, the PEM
fingerprint or a private-key hash. No HMAC or pickle is used.

Vault stores the definition and SHA-256 alongside the reserved UUID in
`<key_name>/_identities/<sha256>`. A first reservation uses CAS=0; concurrent callers
read the winner and compare the source definition. New certificate records also
retain `identity_definition` and `identity_sha256`; renewal preserves them.
Include the identity namespace in backups and scoped Vault permissions. Do not
remove its metadata: it is the persistent identity mapping. A failed creation can
leave a reserved UUID; retry repairs the same identity. An index miss may scan
existing certificate bindings to adopt a unique matching UUID. Multiple matches
fail closed for reconciliation. This is not a cross-store transaction or a claim
of multi-active lifecycle support.
