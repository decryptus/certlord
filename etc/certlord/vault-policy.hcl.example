# Replace the KV v2 mount "secret" and prefix "certlord-certificates" for your installation.
# A role using this policy can permanently destroy certificate versions inside that prefix.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "secret/data/certlord-certificates/*" {
  capabilities = ["create", "read", "update", "patch"]
}
path "secret/metadata/certlord-certificates" {
  capabilities = ["list"]
}
path "secret/metadata/certlord-certificates/*" {
  capabilities = ["read", "list"]
}

# Keep KV metadata/version counters; destroy old certificate material only.
path "secret/destroy/certlord-certificates/*" {
  capabilities = ["update"]
}
