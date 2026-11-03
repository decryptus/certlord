# AWS / CloudFront connector qualification

The read-only preflight and an [experimental renewal job](cloudfront-renewal-job.md)
are implemented in the development source tree, with offline and local acceptance.
Actual AWS account, IAM and CloudFront propagation acceptance remains pending.
Published CertLord 1.2.0 does not include this writer.

The connector is **experimental and inactive by default**. Merging it requires the
normal regression and local integration checks. Actual AWS acceptance is a gate
for promoting this connector to production-supported status, not a prerequisite
for experimental integration or unrelated CertLord releases. No account is needed
for the local tests. See the [explicit activation boundary](cloudfront-renewal-job.md).

## First connector scope

Start with renewal of an already imported ACM viewer certificate, already attached
to one enabled, non-staging CloudFront distribution in the same commercial AWS
account. Require one exact DNS SAN and matching distribution alias, SNI-only serving,
and an explicit certificate ARN in `us-east-1`. Creation, reassociation, shared ARNs,
wildcards/multiple SANs, origin certificates and other AWS partitions are outside
this first increment. These are project scope limits, not general AWS limitations.

AWS documents that reimport keeps existing service associations, requires the same
key type/size, restricts removal of key usages, and does not accept tags. Its
`ImportCertificate` operation exposes no conditional version or idempotency-token
parameter. The future writer must always supply the existing ARN; it must never
fall back to creating a new certificate after an error or lost response.
See [reimport restrictions](https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html)
and the [import API](https://docs.aws.amazon.com/acm/latest/APIReference/API_ImportCertificate.html).

CloudFront viewer certificates require ACM in `us-east-1`; chains exclude the root
and unrelated certificates. Reimport can take up to 24 hours to appear at the edge,
so AWS recommends renewal at least 24 hours before expiry. A successful import or
the distribution's `Deployed` flag alone must not be treated as proof that the
expected leaf is being served. These constraints come from the
[viewer TLS requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html).

## Read-only preflight tool

Run from a source checkout/archive in the contributor environment. This is not a
`certlord` CLI command or a configuration block accepted by the daemon. Its optional
SDK is isolated from product dependencies:

```sh
python -m pip install -r requirements.txt 'boto3==1.43.123' 'botocore==1.43.123'
mkdir -p .local
umask 077
```

Save this synthetic example as `.local/cloudfront-plan.json`, replacing all four
values with the intended test account/resource/domain before a live check:

```json
{
  "account_id": "123456789012",
  "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555",
  "distribution_id": "E123EXAMPLE",
  "domain": "import.example.test"
}
```

Lowercase ASCII DNS names, including already encoded IDNA names, are accepted.
Unknown fields and private-key inputs are rejected. These two commands stay offline
and do not load AWS credentials or require Boto3:

```sh
python tests/integration/cloudfront_preflight.py check-config --config .local/cloudfront-plan.json
python tests/integration/cloudfront_preflight.py policy --config .local/cloudfront-plan.json
```

The policy generator grants only `acm:DescribeCertificate` and `acm:GetCertificate`
on the exact certificate ARN, and `cloudfront:GetDistribution` on the exact
distribution ARN. It contains no wildcard resources or write actions.
`sts:GetCallerIdentity` does not require an added IAM permission. An administrator
must provision the test identity separately; the tool does not attach this policy.
References: [ACM actions/resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_acm.html),
[CloudFront actions/resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html),
[caller identity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).

With an operator-configured read-only SDK profile, explicitly request a live read:

```sh
timeout 60s python tests/integration/cloudfront_preflight.py live \
  --config .local/cloudfront-plan.json --profile certlord-qualification
```

Omit `--profile` only when the intended execution role is provided by the normal
[SDK credential chain](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html).
Do not put credentials in this plan, repository, command arguments or evidence.
The tool checks the caller account before reading the selected resources. It uses
fixed AWS HTTPS endpoints with certificate verification, ignores SDK endpoint URL
overrides, and bounds service connect/read timeouts with no SDK request retry.
The outer `timeout` also bounds credential resolution, which is outside those
service-request timeouts.

The snapshot verifies the configured distribution, its alias and attached viewer
certificate, ACM type/status/usage, the actual returned leaf's SAN and key algorithm,
its validity and more than 24 hours of remaining life. RSA 2048/3072/4096 and EC
P-256/P-384 are accepted when ACM metadata agrees with the leaf. An ACM ARN shared
with another resource is refused. Missing/malformed provider responses fail closed.

Success reports include the domain, ACM leaf SHA-256, expiry, algorithm and observation
time, but omit account/role/resource IDs and PEM. They explicitly leave
`tls_verified`, `write_permissions_verified` and `global_propagation_verified` false.
This is a point-in-time metadata check, not verification of public trust, the leaf
served at the endpoint, effective import permissions, or future absence of concurrent
changes. The private report is not documentation-capture or public CI evidence.
Errors expose fixed codes, never raw provider messages or credentials; the process
returns a nonzero exit code. `check-config` success means syntax only, with
`aws_contacted: false`.

## Writer contract and remaining live gates

The candidate provider job uses the existing
[named destination Auton contract](multi-destination.md#auton-job-contract): UUID,
domain, exact certificate generation and destination. Its own scoped storage
credentials must retrieve current material; keys must never be command arguments.

| Boundary | Writer requirements and production-qualification evidence |
| --- | --- |
| Target binding | Bind account, ARN, distribution, domain and provider-profile revision into the destination configuration identity. Changing the mapping must invalidate old success, even if the Auton URL stays the same. Current daemon profiles do not accept these AWS fields. |
| Material | Validate key match, SAN, dates, chain and ACM reimport restrictions; normalize the provider chain without changing CertLord's stored generation. Retrieve only the selected certificate. |
| Shared effects | Re-read the target and `InUseBy` immediately before writing; reject an unexpected association. This read is not an atomic guard against external AWS configuration changes. Require a controlled single writer. |
| Ordering | Serialize per ARN across jobs and persist intent before sending material. Check current generation while owning that serialization. CertLord's expiring deployment lease alone does not fence an old remote AWS request. |
| Uncertain request | Preserve the attempt and compare provider read-back. Matching material is evidence for that attempt, not a general guarantee that another request cannot arrive later. A crash/lost response with unresolved in-flight effects must quarantine the ARN for reconciliation before allowing a newer generation; do not blindly replay or roll back. |
| Propagation | Separate provider acceptance from observed TLS verification. Use bounded subsequent observations, durable state and a configurable deadline covering asynchronous propagation; never keep a CertLord worker blocked for 24 hours. |
| Completion | Require trusted TLS with the customer's SNI and the exact expected fingerprint. Persist it against the same generation; reject replacement/removal races. One observer does not prove every edge location. |
| Permissions | Qualify a separate writer identity scoped to the existing ARN. Verify reimport with no tags and demonstrate denial on a second ARN. The read-only generated policy intentionally cannot import or update a distribution. |

The no-conditional-write limitation and uncertain-request handling remain part of
the production-qualification review. The experimental writer implements local
serialization and quarantine; read-only preflight alone does not establish their
behavior in AWS. New certificate creation and distribution association need a
separate design. No new deployment states or AWS API options
are being advertised as available in 1.2.0.

## Acceptance and delivery gates

| Stage | Evidence | Current status |
| --- | --- | --- |
| Offline preflight regressions | Wrong account/region/resource, shared ARN, aliases, managed certificate, malformed leaf, key mismatch, expiry, redaction and exact read policy | Implemented in `tests/test_cloudfront_preflight.py`; discovered by normal unittest CI |
| SDK contract | Actual pinned Boto3/Botocore models, stubbed success and AccessDenied, exact request parameters, verified AWS endpoints despite override, no pending responses | Implemented in `tests/integration/cloudfront_sdk_contract.py`; explicit offline Python 3.12 CI job |
| Read-only AWS snapshot | Execute with scoped test identity and existing owned resources | Not run; account/profile and target identifiers are not available |
| Experimental integration | Normal tests, scoped SDK contracts and installed local recovery; no automatic activation | Implemented; 314 unit cases, 11 contracts, five SDK cases, 86 lifecycle and 47 systemd stages pass |
| Live AWS renewal | Owned test domain with public trusted leaf, existing ACM ARN/distribution, approved writer role; import/read-back, observed TLS change and wrong-resource denial | Not run; requires a separate test environment |
| Production-qualified AWS connector | Recorded real-account snapshot, renewal/TLS observation and wrong-resource IAM denial; retain documented scope limits | Pending live evidence; only this promotion is blocked |
| Subsequent CertLord releases | Normal release gates and synchronized versioned packages, images, docs, sites and applicable demos; preserve experimental labeling if included | Independent of AWS qualification; no release is made by this integration |

Run the offline SDK contract explicitly; Stubber intercepts every service call and
uses synthetic credentials and certificates, so this is never AWS acceptance:

```sh
python tests/integration/cloudfront_sdk_contract.py
```

The development wheel includes the optional `certlord.cloudfront` job and
`cloudfront` SDK extra; default daemon dependencies and configuration are unchanged.
This integration is not a published release. Registry versions/descriptions,
Compose, UI captures, demos and product websites remain on stable 1.2.0 until a
separately versioned delivery; they are not frozen pending AWS qualification.
