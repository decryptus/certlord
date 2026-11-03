# Testing and supported scope

Use Python 3.11 or 3.12 on POSIX with the dependencies installed. The test runner
is unittest. Collection parity is checked before executing both discovery roots:

```sh
python -m pip install -r requirements.txt
python .github/scripts/check-test-collection.py --runner unittest tests tests/contracts
python -m unittest discover -s tests -v
python -m unittest discover -s tests/contracts -v
python .github/scripts/check-test-collection.py --runner unittest .github/tests
python -m unittest discover -s .github/tests -v
```

The baseline contains 283 unit cases and 11 component-contract cases. The helper
suite has 19 cases, including one intentional skip for a pytest-only helper
scenario. The project suites themselves use unittest. Empty, incomplete or duplicate
collection must fail. Transport tests require permission to bind local sockets.

CI covers Python 3.11/3.12 with minimum and latest dependency resolution, builds
source/wheel packages and reruns suites against the installed wheel outside the
checkout. See `.github/workflows/tests.yml` and `constraints-minimum.txt`.

The optional Textual suite has two cases and runs separately:

```sh
python -m pip install ".[textual]"
python .github/scripts/check-test-collection.py --runner unittest textual_tests
python -m unittest discover -s textual_tests -v
```

## Disposable integration environments

The lifecycle workflow runs `tests/integration/lifecycle.py` with real disposable
Vault, Redis, Pebble, Certbot and Auton services. It exercises HTTP-01 issuance and
renewal, API authentication and HTTP errors, external certificate import and
replacement, worker failure/restart recovery, served TLS checks, scheduler cycles
and matching remote deployment receipts. All credentials and certificates used
there are generated fixtures; never point these harnesses at production services.
The lifecycle also exercises three named destinations with real Auton jobs and
TLS listeners: one failed destination, persisted progress across restart, a
targeted retry, and replacement invalidating every old fingerprint. The same
installed harness then checks independent TLS endpoints, optional pins, trust/SNI
failures, a requested cycle, unchanged Vault record/deployment counts, Redis
ordering/TTL, stale evidence and reconfiguration across restart. No provider
account or public certificate is required. Unit transport cases also reject an
expired leaf with no pin configured.

### Deterministic HTTP-01 fault tests

The pinned Pebble 2.10.1 compares `rand.Intn(100) > authzReusePercent` when
deciding whether to create a new authorization
([upstream source](https://github.com/letsencrypt/pebble/blob/v2.10.1/wfe/wfe.go)).
Consequently, `PEBBLE_AUTHZREUSE=0` still allows a 1% chance of reusing a valid
authorization. Certbot then legitimately skips HTTP-01. A test expecting a
rejected or held challenge can fail even though the product behaves correctly.

The harness sets reuse to 100%, verifies a distinct renewed certificate with no
new HTTP-01 request, then obtains and deactivates that reused authorization via
the disposable account's ACME API. It checks the returned `deactivated` status
before testing HTTP-01 rejection and scheduler interruption. The single account,
certificate lineage and issued material are preserved; no public CA or production
account is involved. Both ordinary and installed-systemd lifecycle runs use this
setup. Rejection, actual in-flight challenge, retained work and subsequent TLS
recovery assertions remain mandatory. Do not replace them with retries or sleeps.

Failure reports include the worker logs and Certbot's nested/rotated logs, reduced
to traceback locations and fixed diagnostic categories. Raw log lines, exception
messages, account keys, credentials and certificate material are not retained.
Logs that disappear during rotation are reported as unavailable without masking
the original test failure.

The Debian workflow builds a Debian 12 / amd64 package, checks a clean installed
runtime, then uses disposable privileged containers with systemd as PID 1 to
exercise service management and interrupted lifecycle recovery. Read the workflow
before running it: it requires Docker, package-build dependencies and network access.

## What these checks do not prove

The supported topology has one active lifecycle daemon and one authoritative Redis.
Remote jobs may outlive a local command or lease. Deployment jobs must be idempotent;
there is no exactly-once execution or automatic reconciliation of every uncertain
remote outcome. See [operation correlation](operation-correlation.md).

Validate coordinated Vault/Redis backup restoration, real credential rotation and
uncertain remote-job recovery on the intended deployment. CI does not qualify
host-crash recovery, saturation, long-duration stability, arbitrary future dependency
versions or live monitoring-provider accounts. Additional distributions and Python
versions require separate qualification. See [operations](operations.md).
