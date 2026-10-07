<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/svg/logo-horizontal-dark.svg">
    <img src="assets/brand/svg/logo-horizontal.svg" alt="CertLord" width="520">
  </picture>
</p>

# CertLord

TLS certificate lifecycle automation.

Version: **1.0.0rc1 — release candidate**. See the [release notes](docs/release-notes.md).

CertLord automates TLS certificate issuance, renewal and deployment. It supports
ACME through Certbot and importing existing PEM certificates, stores certificates
in Vault and deploys them through Auton. Optional destination TLS verification checks
the certificate actually served before acknowledgement. StatusCake/Updown adapters
are optional; expiry observations are exposed for an external supervision system.
It uses DWho, HTTPdis and Sonicprobe.

Redis stores temporary ACME HTTP-01 challenge responses and tracks pending work,
retries and deployment leases. Vault stores certificate material. Both services
must be provisioned separately; see the [installation guide](docs/debian-installation.md).

## Command line and terminal interface

Use ordinary commands in scripts, or explicitly open the read-only terminal browser
with `certlord tui`. [View the illustrated guide](docs/screenshots.md).

![CertLord terminal inventory with demonstration certificates](docs/images/textual-inventory.png)

Real client capture with synthetic demonstration data; this is not deployment evidence.

## Names and installation

- Python distribution and package: `certlord`
- Command and system service: `certlord`
- Default configuration: `/etc/certlord/certlord.yml`
- Service user and group: `certlord`

Requires Python 3.11+ on POSIX; CI validates Python 3.11 and 3.12.
Newer interpreters are not yet validated. Install the Python package with `python -m pip install .`.
System configuration and external services must also be provisioned. The
Debian 12 package includes an isolated Python environment and the service account;
follow the installation guide before enabling the service.
Repository: https://github.com/decryptus/certlord.
This candidate is intended for evaluation; production acceptance remains deployment-specific.

See [MIGRATION.md](MIGRATION.md) before updating an existing installation.

## Project documentation

- [CLI and TUI screenshots](docs/screenshots.md)
- [Evaluate the release candidate](docs/rc-evaluation.md)
- [Certificate UUIDs, HTTP API, CLI and TUI](docs/certificate-identity.md)
- [ACME HTTP Connector integration](docs/acme-connector.md)
- [Debian 12 installation and isolated dependencies](docs/debian-installation.md)
- [External certificate import and replacement](docs/certificate-import.md)
- [Operations and recovery](docs/operations.md)
- [Operation correlation and optional Auton receipts](docs/operation-correlation.md)
- [Coding conventions and contributions](CONTRIBUTING.md)


Guide: [Certificate observations and supervision](docs/supervision.md).

[Post-deployment TLS verification](docs/tls-verification.md) checks configured destinations before acknowledgement.

[Operations and recovery](docs/operations.md): health, queues, retries and first-version limits.

See [configuration validation](docs/configuration-validation.md) for YAML schema
coverage and compatibility.

## Documentation

- **Users:** installation, configuration, operation and API usage in this README and the user guide.
- **Contributors:** [architecture, tests and development](https://github.com/decryptus/certlord/blob/main/CONTRIBUTING.md).

## Textual terminal interface

See the [Textual guide](docs/textual.md) for installation, navigation and operation confirmations.
