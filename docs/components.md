# Component contracts

| Component | Current tested contract | Limit |
| --- | --- | --- |
| DWho 0.3.63 | Module lifecycle, Redis adapter and worker integration | One authoritative Redis, one active lifecycle daemon |
| HTTPdis 0.6.33 | Actual HTTP authentication, parsing and selected JSON error/status contracts | No exhaustive protocol/security conformance claim |
| Sonicprobe 0.3.56 | Validation, lock behavior and sanitized rejected-value logging | Selected tests do not prove every dependency log is secret-free |
| Auton/autond 1.2.1 | Real job deployment, failure/recovery, optional matching run/status UID receipts | Default command mode has no confirmed receipt; no remote exactly-once guarantee |
| Certbot 5.8.0, certbot-httpreq 0.0.24, acme-http-connector 0.2.1 | Real disposable HTTP-01 issuance/renewal and bound save callbacks | RSA 2048 acceptance; no production CA, wildcard, multi-SAN or DNS-01 claim |
| Vault/HVAC 2.4.0 | KV v2 versioned storage, scoped Token/AppRole, explicit Secret ID replacement, sealed/denied/delayed failures | No host-crash or production backup/restore qualification |
| Redis | Atomic pending associations, deployment leases and guarded cleanup; 4.5.5 client baseline and 8.1.0 lifecycle client | No failover, cross-store transaction or multi-active issuer guarantee |
| dnspython 1.16.0 | Existing resolver/CAA interface, fixtures and blocked-call stop/recovery | Pinned legacy API; not a general DNS policy/RFC audit |
| pyOpenSSL 26.1.0 | PEM/expiry operations exercised in issuance/renewal scenarios | Tested resolver set, not arbitrary future dependency compatibility |
| StatusCake 1.4.5 / Updown 0.1.0 | Optional adapters, response/timeout fixtures; local Updown failure/recovery scenario | Live provider APIs remain unvalidated and disabled by default |

Direct floors and exact minimum constraints are in `requirements.txt` and
`constraints-minimum.txt`. Both minimum and latest resolution are tested, but
transitive versions are not locked. Debian/lifecycle pin external clients as
recorded in their configuration and reports.

## Preserved integration details

Redis prefixes `cert:` and `domain:` are retained. New deployments use
deterministic `deploy:` keys and owner-token `deployment-lock:` leases.
ACME Redis keys remain the request path. Workers retain their existing module
facade methods. Auton credentials remain in the subprocess environment, not
argv. The existing explicit environment behavior is retained: Auton receives
its credential environment (plus optional PATH), and Certbot with `search_paths`
receives a PATH-only environment. Environment inheritance needs a deliberate
policy before changing it, especially for proxies and plugin configuration.

## Current compatibility and unresolved risks

Direct dependency floors now match the exercised local baseline; CI tests pinned
floors and latest resolution on Python 3.11/3.12. See `constraints-minimum.txt`.
real ACME issuance, Vault KV v2 persistence/CAS, Auton deployment, API restart and
lease-owner exclusion are now exercised by the lifecycle workflow.

Commands have deadlines and process-group cleanup. Controlled scheduler shutdown,
silent Vault recovery, HTTPdis Basic permissions and scoped AppRole revocation/replacement
are exercised. Arbitrary blocked provider I/O, host/storage failure, advanced credential
rotation and live monitoring APIs remain separate gates. Locks for other
certificate operations are still process-local; deployment leases do not fence
remote Auton effects. Optional monitoring remains disabled by default; StatusCake
registration is disabled. DNS authorization must be configured explicitly if
required, and its dnspython migration remains open.


## Current issuance and storage protocol (2026-10-02)

The existing connector's configured headers now carry `X-CertLord-Issuance` from
a private per-attempt installer YAML. The JSON body is unchanged. Old callbacks
without identity fail with 409; the installed connector is tested end to end.
Vault removal preserves counters/material-free markers while destroying historical
certificate versions; the current AppRole policy uses metadata read and destroy/update.
Redis membership changes use one-site atomic Lua mutations. See the
[migration](../MIGRATION.md) and [testing](testing.md).
