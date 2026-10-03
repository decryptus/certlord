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

The baseline contains 233 unit cases and 11 component-contract cases. The helper
suite has eight cases, including one intentional skip for a pytest-only helper
scenario. The project suites themselves use unittest. Empty, incomplete or duplicate
collection must fail. Transport tests require permission to bind local sockets.

CI covers Python 3.11/3.12 with minimum and latest dependency resolution, builds
source/wheel packages and reruns suites against the installed wheel outside the
checkout. See `.github/workflows/tests.yml` and `constraints-minimum.txt`.

## Disposable integration environments

The lifecycle workflow runs `tests/integration/lifecycle.py` with real disposable
Vault, Redis, Pebble, Certbot and Auton services. It exercises HTTP-01 issuance and
renewal, API authentication and HTTP errors, external certificate import and
replacement, worker failure/restart recovery, served TLS checks, scheduler cycles
and matching remote deployment receipts. All credentials and certificates used
there are generated fixtures; never point these harnesses at production services.
The baseline scenario contains 78 distinct stages.

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
