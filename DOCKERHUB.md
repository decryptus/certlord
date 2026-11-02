# CertLord

Automate the TLS certificate lifecycle: ACME issuance and renewal, imported PEM
certificates, versioned Vault storage, and deployment through Auton.

## Install

Use the versioned image `decryptus/certlord:{{version}}` for Linux amd64 or arm64.

```sh
git clone --branch v{{version}} --depth 1 https://github.com/decryptus/certlord.git
cd certlord
```

Follow the [Docker Compose installation guide](https://github.com/decryptus/certlord/blob/v{{version}}/docs/docker-compose.md)
to initialize Vault and configure your ACME contact, authentication and destination
jobs before starting the services. The supplied stack starts with Let's Encrypt
staging. Keep persistent volumes and securely retain the Vault unseal material.

## Independent endpoint monitoring

Observe up to 32 configured web, proxy, load-balancer or CDN endpoints without
issuing or deploying certificates. Specify the connection host and TLS name;
trust and hostname validation are mandatory, with optional exact SHA-256 pins.
Read fresh, failed or stale results through the API, CLI/TUI and metrics. These
checks run from the CertLord host and do not prove global CDN propagation.

[Independent TLS configuration](https://github.com/decryptus/certlord/blob/v{{version}}/docs/tls-endpoints.md)

## Deployment and verification

Configure one legacy deployment job or up to 32 named destinations per certificate.
Named destinations each have explicit Auton credentials and a TLS endpoint. CertLord
tracks the job and exact served certificate fingerprint for every target, preserves
partial success across restarts, and offers version-checked targeted retries.
All configured targets must verify before overall deployment succeeds.

Deployment jobs are operator-owned and must be idempotent. An uncertain job outcome
is not proof that it stopped. One active CertLord daemon is supported per state
scope; a single-host Compose stack is not high availability.

- [Multi-destination configuration and recovery](https://github.com/decryptus/certlord/blob/v{{version}}/docs/multi-destination.md)
- [User documentation](https://github.com/decryptus/certlord#project-documentation)
- [Release notes](https://github.com/decryptus/certlord/releases/tag/v{{version}})
- [Source code](https://github.com/decryptus/certlord)

CLI, curses and optional Textual clients expose certificate inventory and details.
CertLord is free software under the GNU GPL.
