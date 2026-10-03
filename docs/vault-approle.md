# Vault AppRole configuration

Vault authentication, certificate storage and HTTP API authorization are independent.
An AppRole grants Vault permissions; it does not grant access to CertLord HTTP routes.

## Scope the role to the certificate prefix

The tested example is [vault-policy.hcl.example](../etc/certlord/vault-policy.hcl.example).
Replace the KV v2 mount `secret` and prefix `certlord-certificates` consistently
with the configured `mount` and `key_name`. It grants:

- token self-lookup, required by the session's authentication check;
- read/create/update/patch on certificate data under the chosen prefix;
- metadata listing and per-record metadata reads under that prefix;
- permanent destruction of prior data versions under that prefix.

Removal permanently destroys prior certificate/key versions while retaining
material-free markers and metadata/version counters. The policy intentionally
omits metadata deletion: resetting the counter would invalidate stale-write
protection after recreation. Grant metadata read and destroy/update before
rolling out this adapter; stop old workers which still delete metadata.
Failed destruction remains visible as pending deletion until an authorized retry.
No access to other certificate prefixes or policy administration is granted.
Provision the policy and AppRole through a separately authorized Vault operator.
The acceptance fixture disables the default policy so its permissions are explicit.

## Configure CertLord

In the protected credentials YAML:

```yaml
vault:
  uri: https://vault.example.invalid
  mount: secret
  key_name: certlord-certificates
  token: '-'
  role_id: '<provisioned-role-id>'
  secret_id: '<provisioned-secret-id>'
```

The explicit `token: '-'` selects AppRole even if `VAULT_TOKEN` is present.
Keep the credentials file restricted to the service account and provide trusted
TLS for the Vault connection. Placeholder values above are not usable credentials.
Choose token and Secret-ID lifetimes/use limits for your operating model; the
test fixture's short lifetimes are not production defaults.

## Revocation and replacement

The session checks the token on access and logs in with its configured AppRole
credentials when the token is no longer valid. This is lazy reauthentication,
not proactive token renewal.

Revoking a Secret ID prevents subsequent logins with it; it does not revoke
already-issued tokens. Emergency revocation must account for both. Once the
current token and Secret ID are revoked, operations fail closed with a storage
error. A new Secret ID can be configured for a newly constructed session.

The acceptance test constructs a new store/session for credential replacement.
It does not implement hot reload of an existing daemon, automatic delivery of
replacement secrets, wrapping/CIDR policies or concurrent token-expiry stress.
Plan a controlled restart for configuration changes until reload is implemented.

See [testing](testing.md) for validation scope and operational checks.
