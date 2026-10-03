# Post-deployment TLS verification

A successful deployment command does not prove that the expected certificate is
served. CertLord can now require a trusted TLS handshake and an exact SHA-256
leaf fingerprint match before acknowledging a configured destination.

## Explicit destinations

Configure one destination per server-generated certificate UUID under
`modules.ssl_certs` (use `certlord show DOMAIN --json` to obtain the UUID):

```yaml
tls_verification:
  timeout: 10
  targets:
    12345678-1111-4111-8111-111111111111:
      host: 192.0.2.10
      port: 443
      # ca_file: /etc/certlord/trusted-ca.pem
```

Use your actual UUID and destination address. The sample UUID/address are not a
working deployment. Targets are trusted administrator configuration, not URLs
submitted by API callers. The host is a DNS name or IP address; the port defaults
to 443. SNI and hostname validation always use the certificate's bound domain,
even when the connection is made to an IP. SAN matching is required; legacy
Common Name fallback is disabled. There is no insecure/skip-verification option.
Omit `ca_file` for system trust roots; a private trust bundle must be an existing
absolute file path readable by the service account. Restart to apply configuration.

An absent target preserves the existing command-success acknowledgement and does
not create a verified result. This check is optional and supports one destination. Adding
a target does not retroactively probe already-deployed certificates.

## Success, failure and retries

After Auton succeeds, the probe checks chain trust, hostname, validity and the
exact fingerprint of the stored leaf captured before deployment. Successful
verification and deployed status are saved in the same conditional Vault write.
Concurrent material replacement/removal invalidates the captured version and
prevents acknowledgement of the old result.

A failed check leaves the certificate `generated` and the deployment queued. A
sanitized failure is persisted with the same version precondition. Subsequent
deployer cycles **rerun the configured Auton deployment command** before probing
again; use an idempotent deployment job. This feature does not introduce a
verification-only retry queue or impose a new retry limit/backoff. Existing
worker intervals and lease handling apply. No automatic remote rollback or
revocation is attempted. A successful command may already have changed the remote
endpoint even though verification fails; pending does not mean nothing changed.

The probe runs in an owned subprocess, with a parent deadline covering DNS,
connect and TLS handshake. Timeout defaults to 10 seconds (positive, at most 300),
plus the existing process termination grace. Scheduler shutdown interrupts it.
The deployment lease covers the larger of command/probe deadlines and is renewed
before and after probes. Lost leases and storage failures cannot become a
successful acknowledgement. Already-submitted remote jobs are not fenced by this
check and may outlive the local command.

## Reading the result

`certlord show DOMAIN --json`, the detail API and observation API expose a
`verification` object, or null when no result is recorded:

- `status`: `verified` or `failed`;
- `checked_at`: UTC timestamp;
- `error_code`: an allowlisted reason on failure;
- expected/observed SHA-256 leaf fingerprints, when available;
- `target_sha256`: fingerprint of the configured destination/domain, not a secret.

Reasons include `tls_validation_failed`, `fingerprint_mismatch`, `timeout`,
`tls_handshake_failed`, `connection_or_trust_store_failed`, `probe_failed` and
`invalid_stored_certificate`. Raw peer/backend errors, key material and trust-file
contents are not returned. Replacement clears the previous result. The result is
historical, tied to the captured material and target: it is not continuous TLS
monitoring, and changing a target or trust file does not refresh an old result.

Prometheus adds `certlord_certificate_tls_verification` (gauge 1, labels UUID and
`status=verified|failed|not_checked`) and
`certlord_certificate_tls_verified_at_timestamp_seconds` for a recorded successful
check. An external supervisor can use the timestamp and status for its notification policy.

## Validation scope

TLS is checked from the CertLord host, against the endpoint reached during one
handshake. This does not enumerate load-balancer backends, prove propagation to
all clients, validate OCSP/CRL revocation, implement STARTTLS/client-certificate
authentication, or continuously detect later changes. A timeout fails closed;
an unreachable internal endpoint must be made reachable or left explicitly
unconfigured, not silently accepted as verified.
