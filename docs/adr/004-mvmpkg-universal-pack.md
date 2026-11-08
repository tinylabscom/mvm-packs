# ADR 004: One pack container, `.mvmpkg`, carrying policy, signature and trace

Status: proposed
Date: 2026-11-06
Related: [ADR 001](001-pack-contents.md), [ADR 002](002-third-party-publishing.md),
[ADR 003](003-embedded-requirements.md),
[prior-art-pack-distribution.md](../prior-art-pack-distribution.md); `mvm` ADR-055

## Purpose

Every pack should be one `.mvmpkg` file that carries, inside the file itself:

1. **Policy**, composable under the existing rules (ADR-055, the product
   requirements' Composable section);
2. **Signature**, so a pack file verifies on its own, offline, against operator trust;
3. **Trace**, in two senses the maintainer asked for together: **build provenance**
   (who built it, from which input digests, on which runtime and base set) and
   **runtime trace identity** (the pack and policy digests threaded into every plan,
   audit and trace record).

Policy-only packs and application packs are the same container. Today they are not.

## Context (what exists, read from the trees on 2026-11-06)

- `.mvmpkg` already exists in `mvm`: a plain tar with `manifest.json` (canonical JSON),
  `manifest.sig` (64-byte detached Ed25519) and `artifacts/`. The manifest schema is
  at version 7, verifiers **fail closed on a newer version**, and it carries typed
  `members` (kernel command line, environment descriptor, embedded boot assets,
  security posture, proofs). Each artifact has a SHA-256 and size; total and
  per-artifact size caps are enforced before reading bytes. The contract also defines
  an OCI `artifactType` and layer media type for a registry manifest whose only
  layer is one `.mvmpkg`.
- A **policy pack** in this registry is not a `.mvmpkg`: a schema-v1 `manifest.json`
  plus `files/` signed keyless as separate files (nine published, immutable).
- An **application pack** is a registry descriptor (schema 2) that pins a `.mvmpkg`
  by digest, size and `key_id`.
- `mvmctl` has a `pack` group (`ls`, `rm`, `info`, `verify`, `update`, `pull`,
  `search`, `lock`, `compile`, plus compatibility names) and a separate top-level
  `new-pack`, `pull`, `search` and `artifact`.
- Two signature roots exist and neither replaces the other: the registry's keyless
  signature over the descriptor, and the bundle's Ed25519 key.

## Decision

### 1. One container, two kinds

A `.mvmpkg` gains a **kind**: `application` (today's bundle: kernel, rootfs, verity,
runtime members) or `policy` (no kernel or rootfs; the policy documents and an
optional README). Both keep `manifest.json`, `manifest.sig` and per-file SHA-256 and
size. The schema version is bumped so every older reader refuses the new bundle at
the version sniff, as the existing ladder does, and exporters stamp the lowest schema
a bundle's members need, so unchanged application bundles stay readable.

### 2. Policy is a typed member

A new member class carries the pack's policy documents (the `profile.toml` /
`group.toml` payload) as signed data, never as something that executes. Composition is
unchanged and shared with ADR-055: ceilings and denies bind the user; a pack's grants
are requests; layers apply in the fixed order; no escape hatches in a pack. To keep
the registry and the client from disagreeing, the rules ship as **shared conformance
vectors** (inputs, layers, expected effective policy) kept in one place and run by
both validators. The policy schema carries its own version.

### 3. Signature is inside the file

Besides `manifest.sig`, a pack carries a keyless Sigstore bundle over `manifest.json`
(`manifest.sigstore.json` inside the archive), naming the publishing identity: the
registry workflow for first-party packs, the author's workflow for community packs
(ADR 002). A pack then verifies offline from the file plus operator trust. Trust
anchors stay outside: the key is never read from the archive, and a community
identity is trusted only when the operator enrolls it. The registry descriptor still
pins the archive digest, size and `key_id`; the in-file signature does not replace
that pin, it makes the pin checkable after the file is copied elsewhere.

### 4. Trace in two parts

- **Provenance.** A signed attestation member (an in-toto-style statement) records the
  builder identity, the input digests (source, base set, runtime), the builder tool
  version, and the digests of the artifacts it produced. The builder version also goes
  into the manifest, so `inspect` can warn on version skew, as the other tool's
  version-skew note does.
- **Runtime identity.** The pack digest (SHA-256 of the canonical manifest) and the
  composed-policy digest are recorded in the signed plan and in every audit and trace
  record, as ADR-055 already requires of the plan. A run can then be traced to the
  exact pack bytes and the exact effective policy.

### 5. Registry representation and distribution

The registry descriptor becomes one kind of manifest that points at a `.mvmpkg` for
both kinds of pack (a new manifest schema; existing schema-1 and schema-2 manifests
stay valid and immutable). Archives are digest-pinned and may be hosted as OCI
artifacts using the contract's `artifactType`; our descriptor validator already
accepts `oci://host/repo@sha256:` sources. A version can list one descriptor per
architecture so an unpinned pull picks the host's. The publisher records verified
archive details (architecture, created time, runtime and builder versions, artifact
hashes, signed environment, policy digest) so pages and `inspect` can show them without
a full download.

### 6. One command group

`mvmctl pack <subcommand>` becomes the single entry point: `new`, `build`, `inspect`,
`verify`, `sign`, `push`, `pull`, `search`, `ls`, `rm`, `update`, `lock`, `compile`.
`new-pack`, and the top-level `pull`, `search` and `artifact` verbs, stay for one
release as deprecated aliases that print the new spelling, then go. Scaffolding
(`pack new`) writes a `pack.toml` plus the right payload for the chosen kind.

## Work, in order

**Now, this repository (no client or format change):**

| # | Item | Size |
| --- | --- | --- |
| R1 | Record verified archive details at signing time and show them on pack pages | S-M |
| R2 | Cache the archive by digest in the publisher gate's CI run | S |
| R3 | Application-pack author guide with a traps list | S |
| R4 | The boot acceptance asserts a value read from inside the artifact, not only a clean boot (recorded on #76) | S |
| R5 | Shared policy-composition conformance vectors (first draft) | M |

**After `mvm` v0.27.0, on branches started now (no merge before the final release):**

| # | Item | Notes |
| --- | --- | --- |
| M1 | `mvmctl pack` consolidation and `pack new` | small, mechanical, aliases kept |
| M2 | Builder version in the bundle manifest; `inspect` skew warning | schema bump |
| M3 | Policy member and the `policy` kind | schema bump |
| M4 | In-file keyless signature and provenance member | needs trust-policy design |
| M5 | Runtime trace identity in plan, audit and trace records | touches the PS-06 audit path: coordinate with its owner |
| M6 | Client transport hardening (digest validation, streaming caps, resumable verified downloads, locks, bounded retries, cache) | large |
| M7 | Per-architecture fan-out under one version | schema and client |
| M8 | OCI-hosted archives, `oci://` source support | client and registry |

**Then:** a new registry manifest schema, new versions of the nine official packs as
`policy` `.mvmpkg` files (the old versions stay immutable and keep working), and
client-floor ordering: new index or manifest fields are not published before the
supported client floor can read them (the `mvm` index contract already says this).

## Constraints and risks

- **Freeze.** `mvm` v0.27.0 is expected around 2026-11-10 and its owner has asked that
  nothing risky land first. Everything in M1 to M8 waits for the final release.
- **Ownership.** The PS-06 lane, the release train and the audit path belong to their
  owner. Format and CLI work happens in separate worktrees and branches, avoids
  PS-06 files, and is coordinated with that owner. The consent record on mvm#3716
  covers signing and publishing a specific pack only; nothing here signs or publishes.
- **Install and start path.** Two open `mvm` issues (an installed bundle stored twice,
  and a persistent start looking for the manifest in the wrong directory) belong to
  another session and land after the final tag. A `policy` kind and any change to
  acquisition or install must be coordinated with that owner first.
- **Rust footprint ceiling.** `mvm` enforces a physical-line ceiling (1,245,000 lines;
  main was about 1,243,900 on 2026-11-06), so there are roughly 1,100 lines of
  headroom. Items M2 to M8 are substantial. Each must be lean, reuse the existing bundle
  member machinery, and be paid for by deletions, or the user must decide to raise the
  ceiling. Moving `new-pack` under `pack` should be net-neutral or negative.
- **Compatibility.** The nine official policy packs are immutable. A client must read
  old and new formats; an old client must refuse the new one by version, not misread it.
- **Parsers.** Every new member, the in-file signature and the attestation are
  untrusted input: size caps before reading, no extraction, no execution, fail closed.
- **Two signature roots stay two.** This ADR does not merge the keyless and the
  Ed25519 roots.

## Open questions

- The attestation format and where its verification policy lives.
- Whether the composed-policy digest is computed by the client or recorded by the
  packer, and what happens when layers differ at run time.
- Whether policy-only packs need an architecture field (probably not).
- The OCI host for archives and who pays for it.
