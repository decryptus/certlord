<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/svg/logo-horizontal-dark.svg">
    <img src="assets/brand/svg/logo-horizontal.svg" alt="CertLord" width="520">
  </picture>
</p>

# CertLord

TLS certificate lifecycle automation.

Version: **1.0.0rc1 — release candidate**. See the [release notes](docs/release-notes.md).

CertLord coordinates certificate creation and renewal through Certbot, external
PEM import and version-checked replacement, Redis-backed HTTP challenges, Vault
storage and deployment through Auton. Optional destination TLS verification checks
the certificate actually served before acknowledgement. StatusCake/Updown adapters
are optional; expiry observations are exposed for an external supervision system.
It uses DWho, HTTPdis and Sonicprobe.

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

- [Certificate UUIDs, HTTP API, CLI and TUI](docs/certificate-identity.md)
- [Architecture and behavior](docs/architecture.md)
- [Component contracts and compatibility](docs/components.md)
- [Tests and staging checklist](docs/testing.md)
- [ACME HTTP Connector integration](docs/acme-connector.md)
- [Debian 12 installation and isolated dependencies](docs/debian-installation.md)
- [External certificate import and replacement](docs/certificate-import.md)
- [Operations and recovery](docs/operations.md)
- [Operation correlation and optional Auton receipts](docs/operation-correlation.md)
- [Coding conventions and contributions](CONTRIBUTING.md)
- [Brand assets](assets/brand/README.md)

## Development checks

Run both suites with the runtime dependencies installed:

```sh
python -m pip install -r requirements.txt
python .github/scripts/check-test-collection.py --runner unittest tests tests/contracts
python -m unittest discover -s tests -v
python -m unittest discover -s tests/contracts -v
```

Build a source archive and a wheel in an isolated build environment:

```sh
python -m pip install build
python -m build
```

Build dependencies (including PyYAML, needed to read `setup.yml`) are declared
in `pyproject.toml`. Direct dependency floors match the tested baseline in `constraints-minimum.txt`.
CI exercises both that baseline and the latest resolvable dependencies.
No automatic package publication is configured.
Debian packaging targets Debian 12 / Python 3.11 on amd64. See the
[installation guide](docs/debian-installation.md) and validation instructions in
[testing](docs/testing.md). Installed-unit start/stop/restart is checked under
disposable systemd PID 1. Controlled stop/restart during issuance and deployment is also verified through
the installed unit. Historical upgrades, host reboot and other distributions
remain separate gates.

Guide: [Certificate observations and supervision](docs/supervision.md).

[Post-deployment TLS verification](docs/tls-verification.md) checks configured destinations before acknowledgement.

[Operations and recovery](docs/operations.md): health, queues, retries and first-version limits.
