# Docker Compose installation

This installation runs one active CertLord daemon, Redis, a persistent Vault and
an authenticated Auton endpoint on one Linux Docker host. It requires Docker Engine
and the Compose v2 plugin. It is not a high-availability deployment.

## Download and initialize

Download the repository so the Compose file and its configuration templates stay
together:

```sh
git clone https://github.com/decryptus/certlord.git
cd certlord
docker compose pull
docker compose up -d vault redis
docker compose run --rm setup init --email you@example.com
docker compose up -d
docker compose ps
```

Use your own ACME contact email. Initialization creates independent random API and
Auton passwords, scoped Vault AppRole credentials and configuration under `.local/`.
It starts with Let's Encrypt **staging**, whose certificates are not browser-trusted.
Running initialization again preserves existing configuration and credentials.

Read your operator login locally with `sudo cat .local/admin-login.txt`. The API
is available only on the host at `http://127.0.0.1:8666`:

```sh
curl --user operator http://127.0.0.1:8666/api/health/ready
```

Curl prompts for the password. HTTP 200 means the scheduler and required backend
probes are ready; it is not proof of successful certificate deployment. See
[operations](operations.md) and the [certificate API](certificate-identity.md).

The image includes the CLI, Textual browser, Certbot connector and Auton client/
daemon. It does not embed Redis or Vault inside the application process. To build
the image locally instead of downloading it, use `docker compose build` before
initialization and `docker compose up -d --pull never` afterwards.

## Protect Vault recovery and persistent data

Vault runs in normal server mode, **not dev mode**. Its data and Redis AOF are
stored in named volumes. Initialization creates one unseal key for this single-host
installation, saves it in `.local/vault-recovery.json`, and revokes the bootstrap
root token after configuration. Application containers never mount that recovery
file and never use the root token.

Copy the recovery file to a protected offline backup. Anyone with it and access to
Vault storage can recover the secrets. The convenience of keeping it on the Docker
host does not protect against compromise of that host; remove the local copy after
backing it up if your policy requires separation, and restore it temporarily when
unsealing. Do not commit or share `.local/`, volume backups or private application
logs. Docker administrators can access container data.

After restarting Vault or rebooting the host, explicitly unseal it:

```sh
docker compose run --rm setup unseal
docker compose restart certlord
```

The recovery file must be present for this command. There is no unattended
auto-unseal in this Compose. AppRole Secret IDs do not expire in this initial
single-host setup; tokens expire after at most four hours and the application logs
in again as needed. Rotate the protected Secret ID using the
[AppRole guide](vault-approle.md).

`docker compose down` preserves volumes. **`docker compose down -v` deletes them.**
Back up Vault, Redis, configuration and deployment definitions together; rehearse
[restoration](operations.md#backups-and-restoration). Replication, Docker restart
policies and a healthy container are not backups.

## Enable public ACME challenge reads

Point the requested domain's DNS to this host and make TCP port 80 reachable. If
port 80 is free, enable the included restricted HTTP frontend:

```sh
docker compose --profile http01 up -d
```

Only challenge GET/HEAD requests are forwarded; administration and mutations are
not exposed. Set `HTTP01_BIND` / `HTTP01_PORT` if another frontend forwards traffic
to this service. The ACME authority still connects to the public domain on port 80.
If you already have Traefik or Nginx, route only the challenge path and read methods
to CertLord as described in the [connector guide](acme-connector.md).

API access remains bound to host loopback. Use an SSH tunnel for initial remote
administration or an authenticated HTTPS reverse proxy with verified TLS; do not
simply publish the administration port on all interfaces. Internal Vault and Auton
HTTP traffic is confined to this Docker host/network. Configure verified TLS when
moving a service to another host.

## Configure the deployment destination

Auton starts with a deliberately failing `/deploy/deploy.sh` job. **It does not
pretend to deploy certificates.** Replace `.local/deploy/deploy.sh` with your
idempotent deployment script, readable by UID 10001. Its directory is mounted
read-only in Auton; use `/var/lib/auton` for temporary work. The job is invoked for
the current batch, without a per-certificate argument: it must discover and deploy
the intended stored material. Grant it separate, read-only Vault credentials for
the needed prefix, rather than reusing CertLord's mutation credentials.

The script must retrieve the intended certificates, install them at your actual
destination, validate service configuration and reload the service. It must exit
nonzero on any failure. Supply SSH keys/trust material through protected files;
the image includes an SSH client but no host keys or passwords. Never mount the
Docker socket just to reload another container. An existing remote Auton endpoint
can be configured in `.local/certlord/credentials.yml` instead.

Enable [destination TLS verification](tls-verification.md) for the relevant
certificate UUIDs. Verify issuance, renewal and the certificate actually served
with staging before switching the Certbot `--server` value in
`.local/certlord/certlord.yml` to `https://acme-v02.api.letsencrypt.org/directory`.
Restart CertLord after configuration changes. Publicly trusted issuance and remote
installation require your DNS and deployment configuration; Compose cannot infer
them.

## External Vault and availability

To use an existing Vault, provision the documented KV v2 policy and AppRole there,
then replace the Vault settings in `.local/certlord/credentials.yml`. Use HTTPS and
a trusted CA. Stop the unused local Vault after verifying the external connection.
The bundled bootstrap/unseal commands operate only on the bundled local Vault;
they must not be used to initialize or manage your existing cluster.

A Vault HA cluster requires independent hosts, Raft quorum, a resilient endpoint
and an unseal strategy. Three local containers do not protect against host failure.
CertLord 1.0.0 still supports **one active lifecycle daemon** per state scope;
do not scale the CertLord service. Redis and Auton availability are separate concerns.

## Updates and logs

The default image is `decryptus/certlord:1.0.0`. Set `CERTLORD_IMAGE` to an explicit
published version or digest when upgrading. Back up first, review release notes,
then run `docker compose pull` and `docker compose up -d`. Re-running setup does
not migrate an existing configuration.

Daemon logs are in the `certlord-data` and `auton-data` volumes. For example:

```sh
docker compose exec certlord tail -n 100 /var/lib/certlord/certlord.log
docker compose exec auton tail -n 100 /var/lib/auton/auton.log
```

Keep logs private and configure rotation/retention for long-running installations.
