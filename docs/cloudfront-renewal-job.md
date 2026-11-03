# Experimental CloudFront renewal job

This is an **experimental, opt-in connector in the development source tree**,
not a supported feature of published CertLord 1.2.0. Offline and local integration
checks pass; actual AWS/IAM and CloudFront edge propagation remain unqualified.
Live qualification is required before promoting this connector as production
supported. It does not block merging the experimental implementation or releasing
other CertLord work. See [qualification gates](cloudfront-qualification.md).

**Inactive by default:** the daemon does not load or schedule this module. The
normal installation does not install Boto3; installing the optional `cloudfront`
extra alone does not activate anything. Execution requires an explicit `run`
command, immutable job profile and selectors, or an explicitly configured Auton
endpoint and CertLord destination. Default service and Compose configurations do
not create a writer. No AWS account is needed to develop or run the local tests.

The job consumes the existing named-destination contract: certificate UUID,
exact domain, generation digest and destination name. It reads that exact Vault
record through a read-only AppRole, reimports into the existing ACM ARN, waits
for matching ACM material, then checks trusted TLS with the domain as SNI. It
never creates an ARN, changes a distribution, adds tags or performs rollback.

## Controlled writer and durable recovery

Run all jobs for an ARN on **one controlled writer host**, with the same private,
durable local state directory. A non-expiring process lock serializes that ARN.
Do not mount a different directory per job, delete the ledger to clear an error,
restore an old ledger while jobs are active, or run another writer/console import
against the same ARN. Multi-host/network-filesystem coordination is not supported.

Before the request, an SQLite transaction records `sending`. A successful AWS
receipt moves it to `accepted`; only matching provider material and an observed
trusted TLS leaf move it to `verified`. The ledger stores fingerprints, profile
and generation digests, intent ID and deadline, never certificate/key PEM.

An exception during import yields `quarantined`. A crash leaving `sending` has
the same blocking effect. Both stop subsequent writes for this ARN, including
newer generations and changed profiles. SDK automatic retries are disabled.
Matching read-back alone **does not prove an earlier request can no longer commit**.
Operator reconciliation is required; do not automate its acknowledgement.

An acknowledged import is never repeated to accelerate propagation. A restarted
job resumes observations using the saved deadline. At an expired deadline it
makes one final observation; a later explicit retry can observe completed TLS
without reimporting. Poll intervals are 1–300 seconds, deadlines 5 seconds–48 hours.
SDK connection/read waits and TLS probes have individual bounds; this is not a
hard bound on all SDK DNS, credential-provider or Vault calls.

Vault generation is checked before import, throughout polling and before saving
success. AWS has no compare-and-swap for this import: a concurrent Vault change
can still race with an already-sent request. The old job cannot acknowledge the
new generation, and uncertainty blocks newer writes. External AWS association
changes are likewise not made atomic by preflight checks. One TLS observation
does not certify all global edge locations.

## Explicitly configure an experimental job

Install the **candidate checkout** in an isolated environment (published 1.2.0
does not contain this module):

```sh
python -m pip install '.[cloudfront]'
install -d -m 0700 /var/lib/certlord-cloudfront
```

The service user must own that directory, the profile and AppRole files. Store
the latter as regular files with mode `0600`, no symlinks. Configure AWS credentials
on the writer host using the standard SDK credential chain or a named profile;
never include credentials in Auton arguments or this JSON. Vault requires HTTPS,
with `ca_file: null` for system trust or an absolute CA bundle path.

Synthetic profile shape (replace identifiers and paths with owned test resources):

```json
{
  "target": {
    "account_id": "123456789012",
    "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555",
    "distribution_id": "E123EXAMPLE",
    "domain": "cert.example.test"
  },
  "certificate_id": "11111111-2222-4333-8444-555555555555",
  "destination": "cloudfront",
  "vault": {
    "url": "https://vault.example.test",
    "mount": "secret",
    "key_name": "certificates",
    "role_id_file": "/etc/certlord-cloudfront/role-id",
    "secret_id_file": "/etc/certlord-cloudfront/secret-id",
    "ca_file": null
  },
  "state_dir": "/var/lib/certlord-cloudfront",
  "poll_interval": 30,
  "propagation_timeout": 172800,
  "aws_profile": "cloudfront-test-writer"
}
```

The AppRole needs `read` on exactly
`secret/data/certificates/<UUID>/<domain>` plus authentication/token self-lookup;
it needs no certificate write, list or delete permission. The AWS writer needs
the [scoped read policy](cloudfront-qualification.md) plus `acm:ImportCertificate`
on the **existing ARN only**. Validate this policy in AWS, including denial on a
second ARN; local Stubber tests cannot prove IAM enforcement.

Generate the profile revision without contacting AWS:

```sh
python -m certlord.cloudfront.job profile --config /etc/certlord-cloudfront/profile.json
```

Use the returned full 64-character `auton_endpoint` as the endpoint name. Pin the
same `profile_sha256` in its command. Deploy each profile revision as an immutable
file and new endpoint; never edit a profile under an active job. The profile hash
covers target, Vault paths, certificate ID, destination, timeouts and state path,
not secret file contents. Secret rotation does not require a new endpoint.

Example endpoint fragment inside an authenticated Auton configuration:

```yaml
endpoints:
  '<full-profile-sha256>':
    plugin: subproc
    users:
      certlord-deployer: true
    config:
      prog: /opt/certlord-cloudfront/bin/python
      args:
        - -m
        - certlord.cloudfront.job
        - run
        - --config
        - /etc/certlord-cloudfront/profile.json
        - --profile-sha256
        - '<full-profile-sha256>'
      timeout: 173100
      disallow-env: true
```

Allow the four appended arguments; the job rejects any other selectors. Limit
this endpoint to the deployment identity. Configure Auton's authenticated HTTPS
origin in CertLord's explicit credential profile with that endpoint name. Define
`deployment_destinations[UUID].cloudfront` using that credential profile and TLS
host equal to the distribution's `*.cloudfront.net` name, port 443, public trust.
The customer domain is used as SNI automatically.

Changing the endpoint changes CertLord's destination target hash and invalidates
old success; do not reuse the old endpoint name for a different AWS mapping.
The daemon's bounded command wait may expire while the remote job continues;
later deployment cycles query the same receipt. Set Auton's job timeout longer
than propagation plus bounded observation overhead. Keep the writer available
and its state persistent across job restarts.

## Inspect and reconcile an uncertain attempt

Read the ledger while the job is running:

```sh
python -m certlord.cloudfront.job status \
  --config /etc/certlord-cloudfront/profile.json \
  --profile-sha256 '<full-profile-sha256>'
```

Stop and investigate the old writer/request using independent operational
information. If it is **not possible to establish that the old request is
quiescent**, keep the ARN quarantined; matching `GetCertificate` is insufficient.
Once that condition is established, record the exact pending intent and current
provider leaf fingerprint and explicitly reconcile:

```sh
python -m certlord.cloudfront.job reconcile \
  --config /etc/certlord-cloudfront/profile.json \
  --profile-sha256 '<full-profile-sha256>' \
  --expected-intent '<intent-uuid>' \
  --observed-fingerprint '<current-acm-sha256>' \
  --acknowledge-quiesced
```

This command performs reads and changes the local ledger to `resolved`; it does
not import anything. A changed intent/profile/fingerprint is rejected. Then use
the existing version-checked destination retry flow. CertLord's
`acknowledge_uncertain` flag alone cannot clear the writer's separate quarantine.

## Evidence and release applicability

Unit tests cover SIGKILL after durable intent, process lock exclusion, generation
replacement, key/usage compatibility, timeouts, missing/wrong TLS fingerprints,
profile revision, explicit reconciliation and private-file checks. The SDK
contract checks exact existing-ARN import parameters and quarantines denied or
wrong-ARN receipts. All SDK service calls are stubbed.

The installed lifecycle adds real Vault HTTPS/AppRole reads, Redis pending work,
authenticated Auton jobs and local trusted TLS. Its controlled HTTP provider
separates import acceptance from serving, tests daemon restart without replay,
and simulates a lost receipt followed by quarantine and explicit reconciliation.
The simulator's completion is known locally; that property cannot be assumed for
AWS. No live AWS account, IAM permission or global propagation result is claimed.

The development wheel includes an optional experimental module/SDK extra. This
integration does not publish a tag, PyPI package or Docker image and does not
activate the connector in a deployment. Registry descriptions, Compose pins,
CLI/UI captures, demos and FR/EN websites continue to describe published 1.2.0.

A subsequent CertLord release can include the opt-in experiment alongside other
changes, provided release notes and affected user-facing surfaces retain the
experimental status and lack of live qualification. Normal artifact, documentation
and deployment checks still apply. Only promotion of the AWS connector to
production-supported status depends on the separate live acceptance record.
Never overwrite the immutable 1.2.0 artifacts or label local simulation as AWS
acceptance.
