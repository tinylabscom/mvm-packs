# ADR 006: Runnable defaults from signed, composable components

Status: proposed architecture; product direction agreed, wire format and client
implementation pending.

Related: [ADR 001](001-pack-contents.md), [ADR 004](004-mvmpkg-universal-pack.md),
[ADR 005](005-runtime-layers.md), [application pack guide](../application-packs.md).

## Problem and goals

A registry pack should be as easy to start as the packaged machine in
Smolmachines: `mvmctl run agent/claude` is **one command** that acquires,
verifies, and launches a working default. It should also compose with other
software and policy without embedding another copy of every shared runtime in
each normal download. A nono-style Claude plugin illustrates a useful optional
extension, but that plugin does not itself distribute a runnable Claude
environment. The registry must not describe an extension as a runnable pack.

The current `agent/claude@2.0.1` is a complete, signed, aarch64 `.mvmpkg` behind
a signed descriptor. It is runnable on a compatible client with the required
host authorization, but it cannot reuse a separately published runtime layer.
ADR 005's layer format and installer are not implemented. Existing published
versions and their signatures remain immutable.

## Approaches considered

| Approach | Advantage | Cost |
| --- | --- | --- |
| Independent, complete images only | One portable file and existing verifier | Repeats base/runtime bytes and cannot compose software into one VM without rebuilding |
| Build software from upstream packages on every user's first run | Flexible inputs and little prebuilt storage | Needs a builder and source trust on the user's machine; slow, failure-prone first run |
| **Prebuild signed runnable defaults and reusable components** | One-command default, digest-pinned composition, shared cache | Requires a component contract and deterministic local assembly for non-default combinations |

Choose the third approach. Keep a self-contained export for users who need
one-file offline portability. Do not make that export the only way to pull.

## Recommended architecture

### Publish once; run with one command

An isolated `builder-vm` resolves pinned sources and builds per-architecture
artifacts: a **complete default image** for each user-facing runnable pack, plus
coarse reusable components (for example a runtime or an optional tool set).
The builder produces evidence but has no release signing or publication
credentials. A protected publisher verifies the outputs, their declared
inputs, policy, and a real boot/workload witness, then signs and publishes
immutable descriptors and artifacts. Reuse the `mvm` compiler, exporter,
verifier, and admission path; this registry is not a second image builder.

The normal `mvmctl run agent/claude` operation selects a compatible published
default, downloads missing artifacts, authenticates the publisher and bundle,
checks revocation and host grants, and starts the **already built** image. It
does not invoke Nix, download an upstream package, or build a filesystem on
first run. A missing provider secret or host grant may require an explicit
interactive approval *within that command*; it must never be granted silently.
An unattended invocation fails with a specific prerequisite rather than
weakening trust. Community publisher enrollment likewise requires explicit
operator approval, not trust on first use.

The proposed `mvmctl run agent/claude --with runtime/python` (assuming a future
published, runnable Python version; the existing policy-only Python version is
revoked) resolves signed, exact-version, digest-pinned components and assembles
a derived ext4/verity image automatically on first use. It caches the measured
result by the full ordered input digests, architecture, assembly format/tool
version, chosen entrypoint, and effective policy digest. A cache hit still
rechecks publisher trust, current revocation state, and runtime grants. A
component is never downloaded or installed inside the guest at startup.

The named runnable pack owns the default entrypoint. Additions cannot silently
replace it. Selecting an alternative command or a second runnable pack's
entrypoint requires an explicit choice; incompatible architecture, conflicting
paths, unsupported dependencies, or unsafe policy combinations fail closed.
An attachable component with no sensible default command is an extension, not
an independently runnable catalog entry.

### Authoring should be short too

Use **one declarative source definition as intent**, not an author-edited
descriptor of an archive they must first build. The author declares a version,
pinned software input, default command, compatible architecture, requested
capabilities, and optional reusable components. Keep a scaffold command for
discovery and an optional local draft check/run under a visibly marked
development trust class. That check is useful for iteration, **not a
prerequisite for submission**; do not require an SDK program or a bespoke CI
workflow for an ordinary pack.

The proposed author fast path is `mvmctl pack publish ./my-pack`. It validates
the source, resolves explicit input versions to a reviewable lock, and submits
the recipe and pinned inputs to the `builder-vm` through one build request (or
one reviewed pull request). The isolated builder produces per-architecture
candidates and tests a real workload. A separate protected pipeline derives
archive hashes and binary pins from the **built bytes**, verifies policy and
provenance, requests the required signing approval, and publishes the signed
artifacts and catalog entry. The author must not hand-calculate hashes, copy
signing keys, construct ext4 images, or coordinate separate release assets. A
failed gate explains which declared input or capability is missing; it does
not publish a partial pack. Publication still requires explicit authority and
must not silently accept an unpinned upstream `latest`.

This authoring flow is a **target**, not a description of today's
`just new-pack` and manual archive preparation. Community author onboarding
may still require one reviewed publisher-identity registration; later versions
should use the same automated build and publish path. First-party publishing
must continue to require its separate, specific release approval.

### Signatures, composition, and revocation

Each published component has an authenticated publisher identity, immutable
digest and size, and a bounded, versioned manifest. Dependency references are
exact manifest-digest pins, not `latest`. The final, published default image
retains its own bundle signature and verification. For a locally assembled
combination, the client verifies every input, measures the assembled output,
and binds the input identities, output hash, entrypoint, effective policy, and
assembly version in a device-scoped authenticated receipt/plan. That local
result is **not** an official publisher-signed pack; deployment policy may
require a separately published, production-signed composition instead.
Neither a signed descriptor nor a local receipt silently enrolls an archive
key or grants a network, secret, or host-share capability.

Policy composition has one authoritative client implementation and shared
conformance vectors: denies win, ceilings narrow, and a pack's requests are
intersected with host/user grants. Verify the signed component policy before
composition and record the resulting policy digest in the launch/audit record.
Recheck every input's revocation status at run time, including when using a
cached derived image. A missing, expired, or rolled-back required feed fails
closed. Fresh revocation data must not be treated as an empty list or make a
cached assembly permanently trusted.

### Distribution, size, and portability

Use content-addressed storage and a shared verified download cache. Compressed
transport can reduce download bytes while preserving the exact verified
uncompressed boot artifacts and verity roots. A complete default image still
contains its own filesystem: **component reuse alone does not shrink that
image**. Measure compressed transfer, actual cross-pack deduplication, cache
size, first-run assembly time, and installed size separately before claiming
a size win; a displayed registry size is not a reliable comparison across
artifact formats.
`mvmctl pack export` may create a self-contained signed artifact for offline
transfer, using the caller-authorized signing path and recording its input
provenance. Export must not claim that locally assembled bytes carry the
original publisher's signature.

## Boundaries and missing pieces

- `mvm` owns component format, assembler, client cache, verity creation,
  signature verification, policy admission, and the run UX. This repository
  owns signed descriptors, catalog/publisher checks, revocation publishing,
  and displayed provenance. Neither repository alone can deliver this design.
- ADR 005 currently says both that a runtime archive has **no key or second
  signer** and that it has an **Ed25519 signature pinned by `key_id`**. Settle one
  component trust contract in `mvm` before making schema v3 publishable.
- ADR 004 proposes a policy-only `.mvmpkg`, whereas the current registry rule
  requires a binary in every published pack. Preserve runnable defaults for
  user-facing packs; decide separately whether non-runnable extensions get
  their own catalog kind. Do not silently relabel legacy policy-only entries
  as runnable.
- The existing Claude pack is a restricted demo. A general coding default
  needs its own explicit software, policy, authorization and workload witness.
  Redistribution rights for the embedded Claude executable remain a release
  prerequisite, not something a signature proves.

## Experiment and decision rule

First, assemble the same Claude-plus-one-runtime workload from pinned inputs
with the existing `mvm` materializer. Verify its final filesystem and verity
root, policy, provenance and actual application output. Measure first and
repeat runs, network transfer, and retained disk use against a prebuilt
default. Prefer materializing and caching a derived ext4/verity image: it
reuses the existing boot/verifier model. Investigate direct runtime filesystem
layering **only if** measured assembly time or disk amplification makes the
one-command experience unacceptable; do not add a second launch trust path
on speculation.

## Open questions

- What device-scoped receipt/plan format does `mvm` already provide, and what
  deployment policies should disallow locally assembled results?
- Which compatible component/architecture combinations are supported first?
- Where should immutable component blobs be hosted, and what are the cache and
  download-size limits?
- Can revocation freshness be supplied externally for immutable default
  images without changing the currently enforced image-set admission rules?
