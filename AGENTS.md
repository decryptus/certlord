# Engineering requirements

These are maintainer requirements.

## Documentation captures

- Capture the actual CLI/TUI output with synthetic data only; never publish host
  inventories, credentials, private keys or internal acceptance evidence.
- Regenerate `docs/images` with `scripts/capture_docs.py` when client rendering,
  command examples or DWho terminal helpers change. Inspect images for clipping,
  readability and misleading success/error colors before merging.
- Keep the capture script, its dependency pins, captions and images together.
  Captures backed by a fixture must be labelled as demonstrations, never as
  successful issuance, deployment or production acceptance.
- Run the documentation capture workflow and check distribution inclusion and
  README/PyPI image links when changing documentation or release packaging.

## Test discovery and execution

- Verify the actual runner and every discovery root before adding or changing
  tests. A green command does not prove that all test declarations were loaded.
  Do not put standalone pytest functions into a suite run only by unittest.
- Run `.github/scripts/check-test-collection.py` with Python, the same
  interpreter/environment as the tests, and the declared runner. Pass separately
  discovered directories together when they are nested. The guard compares
  declarations in `test*.py` files with actual collection; it does not run tests.
- Reject empty suites, import/collection errors, duplicate definitions and
  declarations omitted by the runner. Keep test helpers out of the `test*`
  namespace. Explain intentional skips and separate integration prerequisites;
  never hide failures with `continue-on-error` or `|| true`.
- Run the normal test command after the guard. Report collected/executed/skipped
  counts and investigate unexpected changes; collection alone is not a passing
  test run. Parameterization may produce several cases per declaration.
- Check test paths, naming patterns, selection filters and CI commands together.
  A new test directory or non-Python test harness needs an explicit CI entry;
  this guard only covers the directories and Python naming pattern passed to it.
- Verify installed-package tests outside the source checkout where applicable.
  Architecture scans must resolve the package under test and reject empty scans.
- Preserve supported interpreter matrices. Changing runners requires an explicit
  decision and collection parity; this Python 3.8+ CI helper does not replace
  legacy-interpreter execution or integration/system acceptance tests.

Current project runner: `unittest` for `tests` and `tests/contracts`. CI helper tests use
`unittest` in `.github/tests`.
