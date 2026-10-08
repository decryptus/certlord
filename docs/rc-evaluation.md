# Evaluate CertLord 1.0.0

Use a disposable environment and test domains/destinations under your control.
The steps below evaluate your installation of the stable release. They are an
evaluation plan, not a report that your deployment passed.

An existing production deployment is not required. Use a local test CA and
disposable services for evaluation. Contributors can run the existing automated
[lifecycle acceptance harness](testing.md#disposable-integration-environments).

## 1. Install the published client/package

With Python 3.11 or 3.12 on POSIX:

```sh
python -m venv .venv-certlord
. .venv-certlord/bin/activate
python -m pip install 'certlord==1.0.0'
python -m pip check
python -c 'from importlib.metadata import version; print(version("certlord"))'
certlord list --help
```

This installs software, not a configured service. Provision Vault KV v2, Redis
and an Auton endpoint separately. For the daemon and system service, follow the
[Debian installation guide](debian-installation.md), [Vault access](vault-approle.md)
and [ACME connector guide](acme-connector.md). Use one active lifecycle daemon.

## 2. Configure a controlled destination

Set API authentication/permissions and HTTPS, independent Vault authentication
and storage permissions, and an idempotent Auton deployment job. Keep optional
monitoring disabled unless explicitly evaluated. Configure one
[TLS verification destination](tls-verification.md) per certificate being tested.
The deployment job must validate server configuration before reload and protect
private-key files. CertLord does not supply universal server rollback.

Supply API credentials via a protected execution environment; never place them
in command arguments, documentation captures or committed configuration.

```sh
export CERTLORD_API_URL=https://certlord.example.org
certlord list --json
certlord tui
```

Replace the example URL with your isolated endpoint. The TUI command is optional
and must be run interactively. See the [illustrated guide](screenshots.md).

## 3. Follow one certificate through the lifecycle

Configure a disposable ACME CA before testing issuance/renewal. Do not use public
production issuance merely to exercise retries or failures.

```sh
certlord create www.example.org --json
certlord show www.example.org --json
```

Use a test domain you control instead of `www.example.org`. Record the returned
UUID, poll its detail and inspect pending work. Creation acceptance is not issuance
or deployment completion. Verify stored material, confirmed remote completion
where receipt mode is enabled, and the certificate actually served at the target.
Exercise renewal and confirm the UUID remains stable while material changes.

For existing PEM material, follow the [import/replacement guide](certificate-import.md).
Validate explicit replacement/version conflict handling; imported certificates
must not silently switch to automatic ACME renewal. Never include PEM keys in
an evidence report.

## 4. Exercise recovery before production use

Follow the [operations runbook](operations.md) in the isolated environment:

- Preserve a coordinated backup and restore Vault data/metadata, Redis state,
  configuration and job definitions with writers stopped and remote jobs accounted for.
- Verify identity reservations, versions, pending state and served material after
  restore; retain measured recovery time and any data loss.
- Rotate API, Vault and Auton credentials independently. Check the replacement
  works and the previous credential is rejected after revocation.
- Interrupt communication after remote job submission. Inspect the same remote
  job and destination before replay; do not flush Redis or delete leases to force progress.
- Observe worker progress, pending ages, errors, resource use and destination TLS
  over a recorded interval. Readiness alone does not establish progress.

Keep deployment details, logs and evidence private. Record failures as failures,
not as completed checklist items. The current implementation does not guarantee
exactly-once remote execution, multi-active operation, saturation capacity or
absence of leaks. Review results and remaining limits before using your installation; completing
these instructions does not automatically deploy a service.
