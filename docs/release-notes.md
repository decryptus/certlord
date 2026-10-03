# CertLord 1.0.0rc1

Release candidate prepared on 2026-10-03. This is not the final 1.0.0 release.

## Included

- ACME HTTP-01 issuance and renewal through Certbot and ACME HTTP Connector.
- External PEM import with certificate/key checks and explicit versioned replacement.
- Vault KV v2 storage and separate API/Vault authentication responsibilities.
- Authenticated HTTP administration, CLI commands and an explicitly selected TUI.
- Redis work tracking, deployment leases, retries and bounded worker shutdown.
- Auton deployment, optional confirmed remote receipts and destination TLS checks.
- Authenticated certificate/worker observations and Prometheus metrics.

## Evaluation

Python 3.11/3.12 on POSIX; Debian packaging targets Debian 12 / amd64. Provision
Vault, Redis and Auton separately. Use one active lifecycle daemon and idempotent
deployment jobs. See [installation](debian-installation.md),
[configuration and operations](operations.md) and [testing](testing.md).

After the candidate is published, install its exact version in an isolated environment:

```sh
python -m pip install 'certlord==1.0.0rc1'
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
performed by publishing this candidate.
