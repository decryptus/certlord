# Debian 12 installation

This package targets Debian 12 with Python 3.11; the CI target is amd64.
Build and install only
on the selected distribution/architecture; Debian 13 and newer interpreters are
not covered by this packaging target. See [testing](testing.md) for actual results.

## Package boundaries

[`dh-virtualenv`](https://dh-virtualenv.readthedocs.io/en/latest/usage.html)
builds `/opt/venvs/certlord` during package construction. It includes
CertLord, its Python dependencies, the Certbot HTTP adapter and the Auton client.
The system interpreter remains separate. `/usr/bin/certlord` points into that
environment; the service places its `bin` directory first in PATH.

Building fetches dependencies from the configured package index. The result is
architecture-specific and not a reproducible/offline build: transitive dependencies
are not locked. Installing the resulting `.deb` does not use pip or fetch Python
packages. OS dependencies are still installed by APT. Bundled dependencies require
rebuilding the package for their security updates.

The package creates a `certlord` account and writable state/log directories. Code
stays root-owned. Configuration examples are supplied, but no active configuration,
automatic service start or default sudo grant is installed. Redis, Vault and the
Auton execution endpoint must be provisioned separately.

## Build and install

Use a clean Debian 12 build host/container. The exact build dependencies and CI
commands are in `.github/workflows/debian.yml` and `debian/control`.

```sh
sudo apt-get update
sudo apt-get build-dep .
dpkg-buildpackage -us -uc -b
sudo apt-get install ../certlord_*.deb
/usr/bin/certlord --help
/opt/venvs/certlord/bin/python -m pip check
```

No package release or public APT repository is provided by this workflow.

## Configure before first start

Copy the supplied main YAML example from
`/usr/share/doc/certlord/examples/certlord.yml` (decompress it first if packaged as
`.gz`) to `/etc/certlord/certlord.yml`. Copy the credentials example to
`/etc/certlord/credentials.yml`. Keep both root-owned, group `certlord`, mode 0640.
The daemon must be able to read credentials but should not be able to rewrite them.

Set these deployment-specific values:

- Bind `general.listen_addr` to `127.0.0.1` for an initial same-host setup. Use
  authenticated TLS termination before exposing administration remotely.
- Set a stable `general.server_id`, the Redis endpoints/databases, and an absolute
  `credentials: /etc/certlord/credentials.yml` path.
- Configure Vault credentials, KV v2 mount/prefix and permissions; see
  `etc/certlord/vault-policy.hcl.example` and [migration](../MIGRATION.md).
- Configure the Auton URI, endpoint and any required credentials. The package
  includes the client, not an automatically configured execution server.
- Configure HTTPdis authentication and explicit API operation permissions. For
  disposable loopback-only development, `api_authentication.backend: local` is
  available; it does not provide remote authentication.
- Keep optional monitoring disabled until its credentials and recipients are set.

For HTTP-01 issuance through the connector, run Certbot as the CertLord account
instead of granting root through sudo. Set `modules.ssl_certs.certbot.become.enabled`
to `false`, create writable Certbot directories under `/var/lib/certlord`, and pass
them explicitly with `--config-dir`, `--work-dir` and `--logs-dir`. The HTTP challenge
frontend handles public port 80 separately; the client does not need to bind it.

Copy `/etc/certlord/certbot-httpreq.yml.example` to a protected connector YAML file
readable by the CertLord account. In `modules.ssl_certs.certbot.args`, retain all
required Certbot authenticator/installer options and pass this path for both
`--certbot-httpreq:auth-config` and `--certbot-httpreq:installer-config`.
Use a staging CA until the complete issuance/deployment chain is verified. See
[the connector guide](acme-connector.md) for payloads, callbacks and public GET
routing; the connector's credentials must match the API permissions.

## Start and verify

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now certlord.service
sudo systemctl status certlord.service
sudo journalctl -u certlord.service
```

The systemd unit runs in the foreground as `certlord`, creates `/run/certlord`, and
allows 30 seconds for shutdown. The daemon keeps a file-creation mask of at least
0077, preserving a stricter inherited mask. Raise the supervisor timeout if you increase the
application's worker-stop budget. Service status alone does not prove issuance or
deployment: verify a disposable request through ACME, Vault, Auton and the actual
TLS listener. CLI/TUI access is documented in [certificate identity](certificate-identity.md).

## Upgrade and removal

Before upgrading a legacy installation, stop its workers and back up configuration,
Vault metadata/material, identity index and Redis pending state. Review
[migration](../MIGRATION.md), remove obsolete global Python/Sudo configuration only
after auditing its other users, and adopt explicit paths for the isolated clients.
The package does not remove global Python packages, historical sudo grants, service
accounts or stored certificates on your behalf.

Removal preserves `/var/lib/certlord` and logs. This is not certificate revocation,
remote uninstall or a backup strategy. Review locally managed data before a purge.


## Historical-upgrade acceptance boundary

No historical `.deb` release asset is currently available in this repository.
The retained baseline source (`2ab5aba3584cb291f7cc131e21b0d4ed1cd7492c`)
has an installation script that changes global pip
packages and automatically enables/restarts the daemon. It also installs active
configuration and sudo policy. A configured reinstall of the new isolated package
cannot validate migration of those side effects or of old certificate identities.

Before qualifying an upgrade, retain the exact historical package and dependency
versions, its distribution/Python version, and a sanitized representative state.
Rehearse on a disposable copy with external issuance/deployment disabled, stop old
workers, back up Vault/Redis/configuration, and explicitly review identity/index
migration and sudo/global-Python leftovers. Never execute the historical installer
on a production host just to reproduce its behavior. An upgrade remains an open
gate until that baseline is available and tested; no automatic conversion or
removal of historical permissions is supplied by the new package.

## Optional confirmed Auton job tracking

The isolated package includes Auton 1.2.1. After configuring the single Auton
origin/endpoint and credentials, set `modules.ssl_certs.auton.receipt_mode: true`
if you require a confirmed remote job identity stored with a successful deployment.
Only `--http-timeout` and `--delay` overrides are accepted in this mode; see
[the exact contract and retry limits](operation-correlation.md#confirmed-auton-receipts-opt-in).
Keep the default `false` for an existing custom command configuration until it
has been reviewed. Receipt mode does not cancel remote jobs or reconcile uncertain
jobs after a host crash. Verify the destination TLS configuration separately.

Before production rollout, rehearse the backup, credential rotation and recovery
procedures in [operations](operations.md). Successful installation alone does not
qualify the deployment.
