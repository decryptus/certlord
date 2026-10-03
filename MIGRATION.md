# CertLord configuration and migration

Version 0.0.53 uses the following names and paths. Migration is manual.

| Component | Name or path |
|---|---|
| Python package, command and service | `certlord` |
| Service user and group | `certlord` |
| Configuration | `/etc/certlord/certlord.yml` |
| Shared files | `/usr/share/certlord` |
| State | `/var/lib/certlord` |
| Logs | `/var/log/certlord` |
| PID file | `/run/certlord/certlord.pid` |
| Environment variables | `CERTLORD_*` |
| Exceptions | `CertLordError`, `CertLordConfigError` |

Back up configuration and state, stop the old service, provision the new
account and directories, and copy the existing configuration and state with
appropriate ownership. Update service overrides, environment variables,
sudoers entries, imports, scripts and deployment automation before starting
CertLord. Do not run both services against the same state during migration.

No compatibility command or Python import alias is included. Existing clients
must use the new names. Certificate routes and state fields are described in the [identity guide](docs/certificate-identity.md).
The sample configuration no longer includes an infrastructure-specific CNAME
rule or a fixed DNS verification TXT value. `allow_dns_resolv: {}` disables
this optional authorization check; the CAA precheck remains configured.
For an existing deployment, preserve your intended authorization policy in
your private configuration before replacing the sample configuration.


Copyright notices and historical changelog entries are retained. Package
metadata points to the decryptus/certlord GitHub repository.
Runtime dependencies and known pre-existing bugs are outside this rename.

The sanitized baseline includes the former cleanup and architecture PR changes.
Optional monitoring is disabled and sample contact identifiers are empty.
Author and license notices are retained.


## Vault configuration

Use `credentials.vault`, `vault_check_interval`, and environment variables
`VAULT_ADDR` (or `VAULT_URI`), `VAULT_TOKEN`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`,
and `VAULT_KEY_NAME`. Explicit YAML values win over environment values.
Only these names are supported; obsolete compatibility aliases have been removed.
Managed storage paths are documented in the [identity guide](docs/certificate-identity.md).

## API authentication and infrastructure separation

Certificate routes now authenticate through HTTPdis and then check explicit
`api_authentication.permissions` (`read`, `write`, `deploy`, `challenge`).
An empty permission map denies access. Configure HTTPdis credentials separately
from Vault credentials; give the ACME connector challenge/write permissions and
send its API credentials on its callbacks. Public challenge GET remains public.
For disposable development only, `api_authentication.backend: local` permits
unauthenticated calls when `general.listen_addr` is exactly `127.0.0.1` or `::1`.
Do not expose that listener through an unprotected proxy.

`VAULT_ADDR` is supported as the standard address variable. Explicit YAML values
win over environment values.
The storage mount defaults to `secret` (KV v2). Token and AppRole sessions are
independent of API identities. AppRole can log in again after session expiry;
this is not proactive lease renewal or credential rotation.

Monitoring remains optional inside CertLord. Set `enabled: true` explicitly to
initialize a provider. HTTP handlers no longer perform monitoring initialization.

## Deployment coordination

Certificate workers now require one authoritative Redis server and a shared
`general.server_id` for a shared deployment endpoint. Multiple Redis entries for
certificate state are rejected. Keep KV v2 read/write access: deployment status
updates use the version captured before command launch as a compare-and-set guard.
Failed or uncertain commands retain their Redis lease until expiry before retry.
Remote jobs can outlive that lease; use idempotent deployment operations and
reconcile uncertain remote outcomes. Rollout should stop older worker versions
before starting the new version, since older workers do not honor these leases.

## Vault removal/version-counter migration

The lifecycle implementation replaces metadata deletion with conditional,
material-free deletion markers and destruction of old certificate versions.
The final `removed` marker is hidden from CertLord's managed inventory. Vault
retains metadata path names, counters and non-sensitive markers; old certificate
and private-key versions are destroyed. Existing live records need no rewrite.

Before rollout, update the scoped [Vault policy](etc/certlord/vault-policy.hcl.example):
retain data read/create/update/patch, grant metadata read/list and destroy/update,
and remove metadata-delete permission from the service role. Stop older CertLord
workers before starting the new adapter. Mixing versions or externally deleting
managed metadata can reset counters and invalidate concurrency protection.
A rollback to the previous adapter likewise loses this guarantee.

Inspect and reconcile existing pending work before rollout. The change does not
retroactively protect paths whose metadata was already removed, revoke certificates,
uninstall remote certificates, erase backups or solve late issuance callbacks.


## Managed issuance callback migration

Save callbacks now require the `X-CertLord-Issuance` header bound by CertLord before
launching Certbot. Old callbacks without it return HTTP 409. Roll out the worker
and API together with old workers stopped; do not mix versions. Existing material
remains readable, but unfinished legacy issuance must be retried by the new worker.
This endpoint is not an external certificate-import API.

The CertLord account must read the base installer YAML. A temporary copy (0600,
inside a 0700 directory) supplies the per-attempt header; run Certbot as that account
or root. Do not relax directory/file permissions to support another become user.
Normal shutdown cleans these copies, but SIGKILL/host failure can leave them behind;
clean only confirmed inactive `certlord-issuance-*` temporary directories through
the host's private temporary-file policy. They can contain copied API credentials.
Independent `certbot renew` must not reuse persisted temporary installer paths:
issuance/retry is driven by CertLord's managed worker.

Keep one active lifecycle daemon per Redis/Vault state scope. Atomic membership
updates and deployment leases do not coordinate all issuer/deletion pending state.

## Debian package isolation

The Debian 12 packaging now builds dependencies into `/opt/venvs/certlord` rather
than running global pip from `postinst`. The service uses that environment's
Certbot/Auton clients. Configuration is opt-in and the service is no longer enabled
or started automatically on a fresh install. No default sudo grant is installed.

Stop legacy workers, preserve configuration and data, and follow
[the Debian guide](docs/debian-installation.md) before switching. Historical global
packages, sudo grants and active configurations are not removed automatically.
The supplied YAML still contains historical Certbot privilege settings; set
`modules.ssl_certs.certbot.become.enabled: false` and use writable directories
for a same-account connector deployment. Existing externally customized service
units require review. Refer to the testing guide for the exact validated scope.


### Daemon file permissions

The entry point now tightens its inherited umask to at least `0077` before creating
runtime files and no longer resets it to `0022` while serving. A stricter inherited
mask remains stricter. Newly created files may therefore stop being group/world
readable. Existing file modes are not rewritten: audit existing logs and runtime
files separately, and grant any required group access explicitly. This change does
not alter the packaged `root:certlord` configuration examples or certificate
storage permissions in Vault.


## External certificate import route

Existing active YAML files are not overwritten by package installation. Add this
route under `modules.ssl_certs.routes` to enable the new `write`-authorized API:

```yaml
import_certificate:
  handler: import_certificate
  name: api/certificates/import
  op: POST
```

Restart with the updated code/configuration together. No existing ACME identity
is converted to external ownership. Imported identities explicitly retain external
renewal ownership; see [import policy](docs/certificate-import.md). Changed POST import material is refused; use the explicit version-checked
replacement operation below.


## External material replacement route

Add under `modules.ssl_certs.routes` in existing active YAML:

```yaml
replace_import:
  handler: replace_import
  regexp: '^api/certificates/(?P<certificate_id>[0-9a-f-]{36})/material/?$'
  op: PUT
```

External record metadata now includes `version`. No stored-data migration is
required. Existing `write` permission authorizes replacement; `read` alone does
not. Clients must supply an explicit positive `expected_version`, obtained from
current metadata. Ordinary POST import remains non-replacing. See the import
guide for stale/uncertain responses and deployment boundaries.

## Supervision read endpoints

Add the two GET routes in [the supervision guide](docs/supervision.md) to an
existing configuration. Both use the existing read permission; no stored data
migration is needed. They expose JSON observations and Prometheus metrics, not
notifications or destination TLS verification.

## Optional post-deployment TLS verification

See [the configuration and retry semantics](docs/tls-verification.md). No new route
or storage migration is required. Unconfigured certificates retain their existing
behaviour; configured UUIDs require a successful TLS check before deployment
acknowledgement. Failed checks retain work and retries rerun the Auton job.

## Operational read routes

Add the four authenticated GET routes in [the runbook](docs/operations.md).
No stored-state migration is required. API-only fixtures report live but not ready;
readiness requires a started scheduler and reachable Vault/Redis. The optional
`operation_scan_limit` caps unique observed items and defaults to 10000.
