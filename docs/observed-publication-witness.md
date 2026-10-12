# Publication-only observed witness contract v1

## Review boundary

`scripts/observed-publication-witness.py` is a verifier-only, reviewable contract
slice. It is not integrated into publication. It has no producer, signer, CLI
command, or successful runtime evidence generator. No workflow, release job,
upload tool, consumer admission rule, or image evidence format changes here.
The existing signed image evidence remains byte-for-byte unchanged.

The parser's successful return means **the contract bytes and signatures are
consistent**, not that a released client actually booted an image. A valid
signed report, a signed success assertion, or counters printed by an arbitrary
command cannot authorize publication. The missing protected observer described
below is required before this API can become a publication boundary check.

The eventual report has only the existing
`https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main`
identity and GitHub OIDC issuer. It is not a consumer credential or new trust
identity. The same protected workflow must authenticate the released client,
execute both unpublished candidate probes, retain its own observations, and
only then sign its generated report. Author-provided reports, command logs,
checklists and verdicts must never reach that signing path.

Public pull, consumer admission and boot after publication are separate checks.
They cannot supply the prepublication candidate observation, because requiring
public pull before publishing would be circular.

## Python API surface

- `validate_report(report, trusted_policies)` strictly parses the envelope,
  resolves protected policy bytes, and requires both modes and every declared
  check. It performs no cryptographic verification.
- `validate_raw(report, directory)` checks exact retained file sets, hashes,
  source/candidate/client/policy bindings, and typed measurements parsed from
  raw observation stdout. Call `validate_report` first.
- `verify(directory=..., evidence=..., reference=..., pack_source=...,
  images_lock=..., client_files=..., environment=..., trusted_policies=...)`
  snapshots inputs into private storage, invokes the existing image evidence
  stager's semantic/signature checks, checks raw contents, and verifies the
  report signature. It returns the parsed report. **It is not a publication
  authorization API until the protected observer is implemented and reviewed.**

`environment` is the current protected workflow environment, not report input.
`trusted_policies` is a registry maintained by that same protected workflow:
keys are `(backend, version, sha256)` and values are exact protected-source
policy JSON bytes. Never populate it from a candidate, witness directory,
dispatch-supplied checklist or author output. No production policy registry is
shipped in this slice. Unknown backend, policy digest or version refuses.

The report signature check uses the current publisher identity and issuer plus
cosign's exact GitHub workflow repository, ref and SHA certificate-extension
checks. Run ID and attempt are bound by the signed report and checked against
the independently supplied current workflow environment; no certificate claim
of a run ID/attempt is assumed.

## Strict report envelope

All objects below reject missing and unknown keys. JSON rejects duplicate keys,
nonfinite numbers and type coercion. Schema versions are integers, not booleans.
File records are exactly `{sha256, size}`, using lowercase SHA-256 and an
integer byte size. Signed artifacts and JSON must be nonempty; raw command
streams may be empty and retain their exact empty-stream hash.

The top-level fields are exactly:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1` |
| `kind` | `observed-publication-witness` |
| `source` | Exact `repository`, `ref`, full 40-character `sha`, `workflow_ref`, decimal-string `run_id`, decimal-string `run_attempt`, `invocation`, `publisher_identity` |
| `reference` | Exact versioned pack reference |
| `descriptor` | File record for `image-descriptor.json` |
| `signed_image_evidence` | Exact existing stager evidence file set, including existing signature bundles, each with a file record |
| `images_lock` | Exact independent `images.lock` file record |
| `base_set` | Exact `repository`, `release_tag`, `manifest_sha256`, matching descriptor and parsed lock |
| `client` | Exact `repository`, release `tag`, `architecture`, and file records `archive`, `checksums`, `signature_bundle`, `executable` |
| `policy` | Exact `backend`, integer `version`, policy-byte `sha256` |
| `modes` | Exactly separate `transient` and `persistent` objects |

Each mode contains exactly `transcript`, `commands`, `observations`.
`transcript` hashes the mode's retained raw transcript. `commands` is a
nonempty array of exact objects `{argv, exit_code, stdout, stderr}`. Every
command must have actual integer exit code `0`; any failed command refuses.
The transcript records all executed probe and cleanup commands; a future
observer must not silently omit failures.

Each observation is exactly `{command_index, state, value}`. Its index must
identify a retained actual command. Required checks use `state: "observed"`
and the exact typed expected measurement. Missing, unknown, defaulted, failed,
or unrecognized measurements refuse. `state: "not-applicable"` and `value:
null` are accepted only for a check explicitly declared backend-inapplicable
by trusted policy. Neither a missing check nor an arbitrary N/A is success.

## Workflow-owned backend policy

Exact policy fields are `schema_version: 1`, `backend`, integer `version`,
and `checks`. `checks` contains exactly `transient` and `persistent`; each
has a nonempty set of declared checks and at least one applicable required
check. At most 64 checks are allowed per mode.

Each required check has exactly `applicability: "required"`, `value_type`
(`integer` or `string`), and `expected` of that exact type. An inapplicable
check has only `applicability: "inapplicable"`. There are no author-selected
checks, implicit defaults, global protocol literals or universal jailer/seccomp
requirements. The reviewed backend policy must define its actual lifecycle,
security, persistent-state and cleanup requirements from available measured
APIs. No production check vocabulary or measurement capability is asserted by
the unit fixture's deliberately named `unit_*` checks.

## Retained bytes and raw result parsing

The witness directory contains only:

- `witness.json` and `witness.sigstore.json`;
- `transient.json` and `persistent.json`;
- each mode's zero-based command files, named `MODE-INDEX.stdout` and
  `MODE-INDEX.stderr`.

No field supplies a filesystem path. Raw transcript objects contain exactly
`schema_version: 1`, `source`, `descriptor`, `client`, `policy`, `mode`,
`commands`, binding every command to the same signed envelope.

Each raw stdout result contains exactly `schema_version: 1`, `source`,
`descriptor`, `client`, `policy`, `mode`, `observations`. Its observations map
check names to exact `{state, value}` measurements. The parser derives
`command_index` from the retained command's position, rejects duplicate checks
across command outputs, and requires the aggregate parsed observations to
match the signed report with type-sensitive equality. Raw stderr is retained
and hashed separately. This raw JSON is a contract for the future protected
observer, **not a claim that current mvmctl emits it**.

Hashes alone establish byte binding, not measurement provenance. The protected
observer must capture actual process exits and stdout/stderr itself and parse
real measurement APIs. It must not treat this JSON from an arbitrary command
as an attested runtime observation.

Inputs reject linked paths, special files and linked directory leaves; bounded
small reads also reject hardlinks. Canonical paths are required on systems
whose temporary-directory aliases are symlinks. JSON and raw streams are
bounded to 4 MiB each, retained raw bytes to 32 MiB per mode, commands to 64 per
mode, arguments to 64 per command and 4096 characters per argument. Combined
image evidence and client input sizes are bounded to 64 GiB. The existing
regular-file snapshot copier now supports an optional streaming byte bound;
existing callers retain their previous behavior.

## Missing evidence API prerequisites before integration

The inspected current CLI exposes installed-pack `pack verify --json`,
`machine run` persistence flags including `--up-json`, and runtime-pack
resolution. Those are not a released-client observation contract for this
unpublished built-image descriptor.

Before a producer or publication integration is added, the launch owner must
provide and demonstrate:

1. A released, authenticated client candidate-launch API that binds the exact
   descriptor, rootfs and other signed-image assets without public pull or
   silently falling back to another image.
2. Authentic archive/checksum/signature verification and extraction binding
   the release tag, architecture and actual executed binary digest. This
   verifier binds supplied bytes but does not claim to authenticate a released
   archive, prove archive membership, or execute that binary.
3. Actual separate transient and persistent lifecycle result APIs, including
   entrypoint result, readiness and detach/reattach persistence observations
   where required by the backend policy.
4. Backend-specific measured security observations with documented meanings.
   No protocol version, enforcing verity, jailer, seccomp, egress enforcement,
   listener count or isolation measurement is inferred from metadata or a
   signed counter.
5. Owned shutdown/cleanup observations and a resource census capable of
   detecting incomplete cleanup, including when any probe or command fails.
6. A protected-workflow runner that constructs its transcript from its own
   process execution and observer measurements, signs only its generated
   report, and fixes the allowlisted policy registry from protected source.

Integration stops until these prerequisites are met. The explicit producer is
intentionally absent rather than shipping an unconditional successful
generator or a permanently unavailable command.

## Unit proof, not live proof

Run the contract tests with:

```sh
python3 -m unittest tests.test_observed_publication_witness
```

Tests reuse existing image-evidence fixtures with mocked signatures and raw
unit-only logs. They cover strict schema/policy/type rejection, both modes,
N/A restrictions, failed commands, source/run/attempt replay, every candidate
and client byte binding, rehashed raw binding tampering, signed claims that
disagree with raw observations, signature identity/source options, signature
failure, linked paths, extra files and resource bounds. They do not run a
released client, a VM, cosign signing, or publication.
