# Independent TLS endpoint monitoring

CertLord can inspect the certificate actually served by a web server, reverse
proxy, load balancer or CDN endpoint. These checks are independent of issuance and
deployment: no managed certificate UUID, private key, Auton job or vendor account
is required for an endpoint. The existing CertLord daemon still requires its
configured Vault, Redis and Auton dependencies. This is an optional worker inside
that daemon, not a separate dependency-free service.

## Configure endpoints

```yaml
modules:
  ssl_certs:
    tls_monitoring:
      timeout: 10
      interval: 300
      endpoints:
        web-a:
          host: 192.0.2.10
          port: 443
          server_name: www.example.org
        proxy-b:
          host: proxy.example.org
          port: 8443
          server_name: www.example.org
          ca_file: /etc/certlord/trusted-ca.pem
          # Optional: exact leaf SHA-256, 64 lowercase hexadecimal characters.
          # expected_fingerprint_sha256: ...
```

Replace the example addresses. `host` is the connection address; `server_name`
is the name checked against the certificate SAN and used for SNI when it is a
DNS name. An IP TLS name is checked against an IP SAN. Both fields are required.
Use an IP connection address to inspect a particular server behind a shared name.
The port defaults to 443. System CA roots are used unless `ca_file` names an
existing absolute PEM bundle readable by the service user.

Trust, validity dates and hostname validation are always enabled. A pin adds an
exact leaf check; it cannot bypass those checks. Without a pin, a valid certificate
for the expected name is accepted and its actual SHA-256 is still reported. Pins
are static configuration: update them deliberately when certificates rotate.
They do not follow a managed CertLord certificate automatically. Restart after
changing endpoint configuration or a custom CA bundle. A changed CA file fails
checks until the configuration is reloaded; cached earlier observations remain
valid only until their configured freshness deadline.

Endpoint names match `[a-z][a-z0-9_-]{0,63}`. Up to 32 endpoints are accepted;
an empty mapping disables the worker. `timeout` is 0.1–30 seconds per probe,
including connection resolution and handshake through an owned subprocess.
`interval` is 10–86400 seconds **after a complete sequential cycle**. The first
cycle starts when the daemon starts. Requests arriving during a cycle are
coalesced into another cycle; they do not create concurrent probes.

`stale_after` defaults to `interval + timeout × endpoint count + 30` seconds.
An explicit value must be at least `interval` and at most 604800 seconds. Choose a
value that also covers all sequential checks and backend waits. One active daemon
per state scope remains the supported topology.

## Read results and request a check

```sh
certlord tls-endpoints
certlord tls-endpoints --json
certlord check-tls --json
certlord tui --view tls-endpoints
certlord tui --ui textual --view tls-endpoints
```

The usual API URL, CA and authentication options apply. The terminal browser is
read-only. `r` reloads observations; it does not perform a probe. The displayed
freshness is evaluated at the API read time: refresh to obtain current evidence.
The TLS browser clears old rows on an unavailable read.

| API | Permission | Behavior |
| --- | --- | --- |
| `GET /api/tls-endpoints` | `read` | Snapshot of configured endpoints and stored observations |
| `GET /api/tls-endpoints/metrics` | `read` | Prometheus-format freshness, verification and last-check gauges |
| `POST /api/tls-endpoints/check` with `{}` | `write` | Wake the configured worker; `accepted` is not a successful check |

Existing installations must merge these three routes from `etc/certlord/certlord.yml`
before using the new API. Neither GET route performs network probes. POST accepts
no endpoint override and never issues, replaces or deploys a certificate. Requests
with arbitrary destinations are rejected. A stopping daemon refuses the trigger;
a disabled monitor returns `accepted: false`.

Each record exposes the connection host, port, TLS name, optional expected and
observed SHA-256, `checked_at` (Unix seconds), `fresh`, `status`, `last_status` and
a sanitized `error_code`. `verified` requires a fresh successful observation.
`unknown` means no evidence for this configuration; `failed` reports the most recent
fresh failure; `stale` retains the historical result without counting as verified.
The aggregate is `disabled`, `unknown`, `failed`, `partial` or `verified`.
A Redis failure or malformed evidence returns HTTP 503, not empty success.

Redis keys are scoped to the server identity, endpoint name and complete normalized
probe configuration, including custom CA content. Restart retains matching evidence;
changed configuration starts unknown. Old writes cannot replace newer observations.
Keys expire after `max(3600, 2 × stale_after)` seconds. No certificate material,
private keys or raw backend errors are saved in these records. The optional worker
also appears in readiness and cycle observations.

The metrics use only configured endpoint names as labels:
`certlord_tls_endpoint_verified`, `certlord_tls_endpoint_fresh`, and
`certlord_tls_endpoint_checked_timestamp_seconds`. Alert on verified = 0, with
freshness/last-check gauges to distinguish a failed check from missing or old data.

## Observation limits

A check observes one connection from the CertLord host at a particular time.
A DNS connection does not enumerate every address; a CDN endpoint does not prove
that every point of presence serves the same certificate. No geographic probes,
provider provisioning, automatic remediation or notifications are added here.
Use separate endpoints or an external monitoring service when those are needed.

The [synthetic interface captures](screenshots.md) demonstrate these states.
They are not evidence about a public domain or a deployed production certificate.
