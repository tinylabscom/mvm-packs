# PS-06 protected observer v2

## Status and authority boundary

This is the code-controlled, pre-integration slice of the approved bounded
protected-policy architecture. It is **not SignedBuilt evidence**, a protected
execution witness, or publication authorization. Schema v1 remains a historical
contract only; producer acceptance is v2-only, with no fallback, legacy role,
hybrid envelope, or implicit role.

The producer and publication wiring remain disabled. No production backend
policy, receipt adapter, authenticated Release A/B pair, or protected run is
introduced by this change. Unit fixtures deliberately model nonexistent
release artifacts and mock signature verification; they do not implement
measurement APIs. Passing them cannot establish that a guest ran.

## Implemented diagnostic subset versus future producer contract

`scripts/protected-observer-v2.py` is an import-only diagnostic module, not a
producer. Its top-level fields are exactly `schema_version`, `kind`,
`source`, `reference`, `clients`, `producer_sha256`, `candidate`, `policy`,
`artifacts`, `signed_image_evidence`, `images_lock`, and `base_set`.
All are mandatory; earlier diagnostic envelopes missing them refuse rather
than downgrade. The kind is deliberately `protected-observer-diagnostic`, not a
claim of a successful protected observation.

`artifacts` contains exactly `transient` and `persistent` opaque file records.
These records bind bytes only. They do not authenticate a session, parse a
runtime receipt, establish command exits, or satisfy runtime policy.
`require_publication_authorization` always refuses. A successful diagnostic
return must never be wired to upload or admission.

The final producer contract still needs independently reviewed lifecycle
measurement semantics and complete probe-to-current-run/base/lock/revocation/
admission bindings. The diagnostic subset is not that final contract. There
is no fallback to the historical v1 parser to fill these gaps.

### Diagnostic API and trusted inputs

- `validate_report(report, trusted_policies, *, environment, checkout_sha,
  workflow_sha, trusted_registry, producer_sha256=None)` validates structure,
  source/run/attempt, distinct A/B/H and protected policy selection. It does
  not authenticate the referenced client/candidate/artifact bytes.
- `verify_client(client, directory, *, source)` snapshots the four existing
  released files, verifies both signed subjects with cosign, checks the unique
  exact archive checksum, and returns the exact bounded x86_64 ELF member bytes.
  It never executes the client. `observed_source` is explicitly an unsigned
  acquisition-context observation, not an authenticated release commit.
- `verify_candidate(candidate, directory, *, source, reference)` verifies the
  exact manifest signature, canonical publisher manifest/image schema, complete
  local-transport inventory, and the canonical provenance statement's
  rootfs subject, reference/base, producer pin, builder, source and run.
  It reuses the existing publisher statement constructor. Candidate, layer
  and images-lock digests remain declared dependencies, not independently
  authenticated base/lock inputs in this API.
  Its parsed-manifest return is not an admitted candidate or a retained
  immutable install snapshot.
- `resolve_policy(binding, trusted_policies, *, source, trusted_registry)`
  checks independent registry and selected-document byte records. Both trusted
  inputs must be obtained by reviewed protected code, never from the report,
  dispatch, candidate or author.
- `verify_diagnostic(directory=..., evidence=..., candidate_directory=...,
  client_directories=..., images_lock=..., reference=..., environment=...,
  producer_sha256=None)` composes source loading, strict report validation,
  both authenticated client archives, canonical candidate verification,
  existing signed-image semantics/signatures, and the signed diagnostic report.
  It snapshots evidence and raw artifacts privately. Each image asset must
  equal the canonical candidate transport asset; descriptor, base, verifier,
  current source/run/attempt and lock bytes must agree.
  Opaque mode hashes are checked, but no runtime receipt is parsed.

`scripts/protected-observer-source.py::load_source(environment)` supplies
policy bytes only from the script's own fixed repository root and fixed paths.
It requires the trusted GitHub job environment's `GITHUB_WORKFLOW_SHA` to equal
`GITHUB_SHA` and actual Git HEAD, a clean checkout including untracked files,
no index flags hiding tracked changes, regular nonlinked input files and exact
committed blob bytes. Git routing variables and replacement objects cannot
select alternate content. The fixed workflow file is
`.github/workflows/publish.yml`; the fixed registry is
`.github/policies/protected-observer-registry-v2.json`.
The derived `pack-sources/<namespace>/<name>/pack.toml` is independently checked
against the same immutable Git commit, not a user-selected source path.

The loader checks consistency with a **trusted job environment**, not the
authentication of an arbitrary local dictionary. Unit mini-Git environments
are not authenticated GitHub executions. No production policy files are shipped,
so an actual loader invocation refuses until reviewed protected source contains
them; there is no report/dispatch/candidate policy override.

The diagnostic registry is exactly `{schema_version: 2, policies: [...]}`.
Each entry is exactly `{path, role, backend, version, document}` and selectors
`(role, backend, version)` must be unique. The binding adds exact `source` and
`registry` byte records; `document` separately binds the selected policy SHA
and size. The workflow-owned document lookup key is `(path, role, backend,
version, repository, ref, sha, workflow_ref, document_sha256)`.

The fixed selected-document path is
`.github/policies/protected-observer-v2.json`. Diagnostic documents contain
only `{schema_version: 2, role, backend, version}`. These are **not runtime
checklists or backend applicability policy**. The runtime policy vocabulary and
reviewed measurement adapter remain integration work. The composed diagnostic
uses trusted `GITHUB_WORKFLOW_SHA`, not report JSON, for workflow-source binding.

Resource bounds in this diagnostic implementation are 256 payload files,
256 MiB per payload/client record, 4 MiB per metadata/artifact record, and
64 policy selectors. Canonical zero-byte payload files are supported. The
archive permits only its exact binary and optional parent directory. No live
release-layout/size compatibility is claimed before authentic A/B are tested.
Fixed-size tar headers are inspected before reading member bodies; PAX/GNU
extensions are rejected before their declared metadata sizes can trigger an
unbounded decompression/read.

## Closed authority and subject table

| Role | Exact subject | Existing signing authority |
| --- | --- | --- |
| Producer A / observer B release archive | Exact named Linux x86_64 archive bytes | `https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/<tag>` |
| Producer A / observer B release checksums | Exact checksum text naming that archive | Same release identity for that client's tag |
| Image evidence | Each exact existing image-evidence subject with its corresponding bundle | `https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main` |
| Private candidate | Exact `manifest.json` bytes, with exact manifest bundle retained | Same current packs publisher |
| Observer report | Exact v2 report bytes | Same current packs publisher |

The issuer is `https://token.actions.githubusercontent.com`. Purpose strings and
role labels select a closed verification rule; they never confer authority.
Bundles must authenticate the actual subject, not another subject with the same
role label. The former repository signer is not accepted for new evidence.
The diagnostic pipeline implements release, candidate, existing image-evidence,
and diagnostic-report signature paths with actual fixed subjects and source
binding. The existing canonical stager accepts an optional source-bound
signature callback; its publisher default behavior remains unchanged. The
final runtime observer `report` role still refuses: a signed diagnostic report
is not an authenticated measurement report and cannot authorize publication.

For each client, retain repository, tag, **observed** source context,
architecture, archive, checksum text, checksum bundle, archive bundle, executable
member name, and exact executable digest/size. Authenticate both signed blobs,
require a unique checksum entry naming the exact archive, and extract only the
exact regular executable member, rejecting aliases and links. A repository
checkout SHA or release API response is not an authenticated release source
commit. Only existing signed metadata could establish such a claim.

## One global verifier pin

`H` is the exact SHA-256 of producer A's executable extracted from its
authenticated archive. It is not an archive digest, B's executable digest,
per-architecture setting, guest digest, version output, or JSON claim.
`TRUSTED_IMAGE_VERIFIER_SHA256 = None` continues to refuse ordinary Built
admission. Never substitute a report-supplied value for this trusted setting.

A and B must be distinct authenticated clients. B must independently install and
admit the exact private candidate using normal publisher identity, revocations,
accepted base/lock, and Built checks. Candidate provenance must bind
`verifier_sha256 == H`. The first live lane is only Linux x86_64 A, Linux x86_64
B, and x86_64 guest. No cross-platform acceptance is inferred.

## Protected policy and replay

Only a fixed path in reviewed protected workflow source can supply policy
registry bytes. Bind the packs repository, `refs/heads/main`, full commit,
policy path and role, registry digest, selected-policy digest, and exact
backend/version/role entry. The authenticated workflow source SHA must equal
the checked-out HEAD. A report, candidate, dispatch, or author cannot supply
policy bytes or verdicts. Unknown policy or unavailable applicable measurements
refuse; N/A requires explicit trusted backend inapplicability.

The report and each probe/receipt must bind the same protected workflow run ID
and attempt, checkout, candidate, A/B, base/lock, selected policy, revocation and
admission context. No reuse across retries or runs. Current revocation/admission
must be rechecked before public publication and again on consumption.

## Exact candidate, no second publisher

Reuse the canonical publisher, existing private candidate path and existing
signer. Bind the signed manifest, its signature bundle and a complete canonical
payload inventory of normalized path to exact SHA-256 and integer size.
Reject missing/extra files, path aliases, duplicate JSON keys, symlinks,
hardlinks, and non-regular file ambiguity. B's supported import command is:

```sh
mvmctl pack registry install-local <ref> --manifest-sha256 <sha> \
  --manifest <manifest.json> --bundle <manifest.sigstore.json> --files <files-dir>
```

Do not execute this until a compatible released B and the global pin exist.
Public publication must preserve the observed signed bytes, including bundle
and inventory. Any rewrite or re-sign requires a new protected observation;
an equivalent parsed manifest is not byte identity.

## Runtime receipt blockers

PS-15 owns release/runtime verification and the rehearsal; PS-21 owns the
lifecycle/supervisor. They must supply and review actual APIs before integration:

1. Release-proof verification and selected overlay, verity, initramfs, root and
   protocol verification against the **same immutable `VmStartConfig`** that
   the lifecycle owner snapshots before backend start.
2. Launch/session receipts linking the admitted candidate and plan, final
   config, backend, selected runtime and current protected run. Keep
   `bundle_boot_assets` separate; SDK-sidecar attachment must fail closed.
3. Separate transient and persistent lifecycle observations, real command
   exits, raw stdout/stderr, expected input consumption and associated output,
   stop/start persistence, and owned cleanup/resource census.
4. Actual backend-specific isolation and transport measurements. There is no
   universal protocol, security or I/O assertion. Do not claim no NIC/TAP/TUN,
   authenticated-vsock peer, input consumption, or output association from
   configuration, signed counters or synthetic fixtures.
5. A protected runner capturing its own command exits and streams, resolving
   only protected policy bytes, and signing only its own completed report.

The command
`mvmctl env verify-runtime --config FILE --version 0.24.0 --arch x86_64 --json`
is diagnostic only, not launch authority or a retained-runtime receipt.
PS-15 confirmed the source-side contract: `verify_release_runtime_for_launch`
returns a typed `VerifiedRuntimeManifest` carried by `PreparedBuiltPackRuntime`;
`verify_config` rechecks archive SHA before dispatch against the same immutable
configuration snapshot. These are source-level guarantees, not proof of a
released API or an externally observable session. `plan.admitted`,
`plan.launched`, `plan.failed` and exact-pin registry events do not establish
device inventory, authenticated peer/session, guest input consumption or
image-associated raw output/exit.

PS-21 separately confirmed that a reviewed immutable **final** configuration
measurement receipt API is not available. Its proposed ordering is canonical
runtime reauthentication and owned-path snapshot, final CPU/Wasm/policy gates,
then a private client seal before backend effects. Those proposed operations
must not be represented as an existing public observer DTO. Actual native-child,
Ready, guest-authentication and stop/reap observations are still needed.

Supported #4446 launch shapes, pending release/API recheck, are:

```sh
mvmctl machine run --policy <signed-pack-ref> -- <command>
mvmctl machine run --policy <signed-pack-ref> --name <name> --detach
mvmctl machine stop <name>
mvmctl machine start <name>
```

A one-shot Python version boot, source-pack tests, Go policy pack, CLI JSON,
signed counters and synthetic unit reports do not meet these requirements.

## Live acceptance remains open

As refreshed during this implementation, mvm #4409 is open at
`6021cf5f1381506d74637da0aefba57543af7133` and reports merge conflicts.
mvm #4446 is open at `ec6d7c0aad79024d9829c1904dd29a84e14071ea`, stacked on
`feat/3724-runtime-assurance`; completed non-skipped checks succeeded, but CI
success is not a release or runtime witness. Packs #12 is an open **issue**
with six unchecked production gates. #63 is verifier-only and #64 is unsigned
private-candidate preparation.

Do not close mvm #3716/#3731 or mark PS-06 complete on this change. Completion
requires the protected prepublication observation, a public signed
image-bearing pack, and a fresh recipient using released B to pull, reverify,
admit and boot in both modes, including expected input/output, audit/plan
linkage and measured isolation/transport. No workflow dispatch, signing,
upload, publication, tagging or paid/cloud operation is authorized here.

### Critical path and ownership

| Gate | Owner | Missing evidence / action |
| --- | --- | --- |
| Compatible Release A | PS-15 | Land reviewed prerequisites through normal CI; resolve the full native-release pathname-ownership gate. No authenticated A executable hash is available. |
| Immutable final config and actual session measurements | PS-21 lifecycle owner, coordinated with PS-06 integration owner | Review and implement the real receipt contract after final mutations, before backend effects; no serialized-config proxy. |
| Global H and compatible Release B | PS-06 integration owner + PS-15 | Review A's authenticated executable hash as the single compiled pin, then produce and authenticate distinct B. |
| v2 byte/source/role/replay contract | PS-06 observer owner | Complete code, adversarial unit tests and focused review without enabling execution. |
| Protected candidate observation | PS-06 integration owner | Obtain real receipt adapter and explicit execution authority; run both modes against the exact signed candidate with current admission context. |
| Public pack and fresh-recipient acceptance | PS-06 + PS-15 rehearsal owner | Reuse exact observed signed bytes, recheck current revocation/admission, then retain released-B pull/admit/both-mode runtime evidence. |

These are dependencies, not completion estimates. A deadline does not turn a
missing measurement into N/A or authorize signing/publishing ahead of review.
