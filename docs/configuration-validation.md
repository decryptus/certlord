# Configuration validation

The daemon uses an explicit parser hook to validate application sections before
DWho resolves credentials and normalizes defaults. The certificate module repeats
the application checks before route registration so imported module settings are
covered too. API/storage backend choices, permission lists, checker enabled
booleans and certificate command/TLS/DNS configuration mappings use XYS.
Module registration may validate a partial configuration; the daemon parser still
requires general through DWho. Vault credentials are never API permissions.
Authorization, finite timeouts, DNS policy and provider-specific validation remain
with the existing services and adapters.

XYS (Sonicprobe >= 0.3.57) validates parsed Python data; it does not replace the
YAML loader, resolve imports, initialize services or grant permissions. Schemas
are compiled once. These schemas use no modifiers and do not silently convert
values. The existing numeric normalization and semantic checks still apply.

Known application fields are validated explicitly. Extension settings remain
available where the existing contract permits them; this is not universal typo
detection for plugin configuration. Malformed section/component shapes now fail
with a configuration error instead of incidental attribute/update exceptions.
New validation errors do not include configuration values or credential contents.

`tests/test_configuration_schema.py` covers valid/invalid shapes and compatibility
at the loader boundary. Run the collection guard before the unittest suite:

```sh
python .github/scripts/check-test-collection.py --runner unittest tests tests/contracts
python -m unittest discover -s tests -v
python -m unittest discover -s tests/contracts -v
```

These tests use synthetic data and mocked adapters or loopback services. They do
not establish provider availability or production acceptance.
