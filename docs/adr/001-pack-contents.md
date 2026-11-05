# ADR 001: What a pack contains

Status: accepted
Date: 2026-11-05
Related: [#31](https://github.com/tinylabscom/mvm-packs/issues/31),
[#76](https://github.com/tinylabscom/mvm-packs/issues/76)

This repository had no ADR directory; `docs/adr/` starts here. Nothing in
`tests/` or `scripts/` validates files under `docs/`.

## Purpose

Packs exist to provide official, signed software, the expected bits, that
runs with its own policy. That policy composes with the user's policy and with
other policies in a defined precedence (see Policy composition). A pack is
therefore two things bound together: the software (application packs only)
and the policy it ships with (every pack, including policy-only ones).

## Context

The word "pack" names two different things in this registry. The published
`agent/claude@1.0.1` is a policy pack; it is not a runnable Claude Code
environment (`CLAUDE-ENVIRONMENT.md`, `AGENTS.md`). A runnable replacement
needs an application. Without a written rule, a policy-only name can be
mistaken for something that boots. This ADR records what each kind holds,
which bytes each digest and signature covers, and what is currently published.

## Decision

### 1. Two kinds of pack

**Policy pack.** A declarative capability profile and nothing executable.
`packs/agent/claude/1.0.1/` holds `manifest.json`, `manifest.sigstore.json`
and `files/pack/profile.toml`. The manifest (schema v1) carries `reference`,
`description` and a `files` list of `{path, sha256, size}`. The profile names
policy groups (`llm-apis`, `github`, `runtime/python`) and one secret binding
(`anthropic`, host `api.anthropic.com`), by name only. Sources are
`pack-sources/<ns>/<name>/pack.toml` plus `pack/profile.toml` or
`pack/group.toml` (`README.packs.md`, "Layout").

**Application (environment) pack.** A signed portable `.mvmpkg` plus a
registry descriptor that pins it.

- The `.mvmpkg` is the `mvm_core::plan::bundle` archive: `manifest.json`,
  a detached 64-byte Ed25519 `manifest.sig`, and `artifacts/` (kernel,
  rootfs, optional dm-verity sidecar, base config, optional initrd)
  (`crates/mvm-core/src/plan/bundle.rs`; DTOs in
  `crates/mvm-contract/src/plan/bundle.rs`, in the `mvm` repository). Its
  manifest records `arch`, `key_id`, per-artifact SHA-256, advisory
  `resources`, and members such as the kernel command line, security posture,
  build provenance and an `EnvironmentDescriptor`
  (`crates/mvm-contract/src/plan/environment.rs`). The environment descriptor
  carries the entrypoint, resources, an egress ceiling (`policy`), logical
  `secret_slots` (names only) and required capabilities.
- The registry descriptor is a manifest with `kind = "application"` and exactly
  `schema_version`, `kind`, `reference`, `description`, `application`. The
  nested `application` (schema 1) holds `guest_arch` (`x86_64` or `aarch64`) and
  `bundle` = `{source, archive_sha256, archive_size, key_id}`
  (`scripts/application_manifest.py`, `validate_application`). The published
  version directory holds only `manifest.json` and `manifest.sigstore.json`;
  no `files/`.

A policy pack alone is not runnable: it has no kernel, rootfs, binary or
entrypoint. A safe application release requires the completed archive and all
its boot assets, read back and verified against the descriptor's digest and
size. Before signing a new application version, `build-packs.py` reads the
archive back over HTTPS and refuses on any size or SHA-256 mismatch, an
unreadable source or a non-HTTPS source. That is an integrity check only: it
does not verify the bundle signature or its contents, which still need the
separate artifact verification.

### 2. How index, manifest, descriptor and archive relate

| Object | Pinned by | Authenticated by |
| --- | --- | --- |
| `index.json` (schema v2) | nothing; discovery only | not signed (`README.packs.md`) |
| `manifest.json` (policy or descriptor) | `manifest_sha256` in `index.json` over the exact published bytes | `manifest.sigstore.json`, keyless, workflow identity `https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main` (`.github/workflows/publish.yml`) |
| policy `files/*` | `sha256` and `size` in the manifest | transitively, through the signed manifest |
| `.mvmpkg` archive | `archive_sha256`, `archive_size` in the descriptor | the descriptor signature covers the pin, not the archive's trust |
| `.mvmpkg` contents | per-artifact SHA-256 in the bundle manifest | Ed25519 publisher key whose `key_id` is in the descriptor |

Two signatures, two roots, neither substitutes for the other. The keyless
signature says the registry workflow published the descriptor. The bundle
signature says the holder of one publisher key sealed the archive. A
descriptor does not enroll its `key_id`; the consumer must already hold that
public key in its own trust store (`~/.mvm/trusted-publishers/<key_id>.pub`),
and the key is never read from the archive. The consumer side is
`crates/mvm-core/src/registry_pack/application_bundle.rs` in the `mvm`
repository: it checks archive size and digest against the descriptor, the
bundle signing key against the descriptor `key_id`, and the architecture, then
runs the existing bundle verification. Launch re-authenticates the cached
descriptor and archive and rechecks revocation (`application_bundle/launch.rs`).
Neither step is launch authorization; bundle admission still decides.

### 3. Namespaces, versions, immutability, revocation

- A pack is `namespace/name@version`, taken from folder coordinates and
  `pack.toml` `version` (`README.packs.md`).
- Published bytes never change. `build-packs.py` refuses a changed source
  until the version is bumped. A runnable replacement of a policy-only name is
  a new version (for example `agent/claude@2.0.0`), never an edit of 1.0.1.
- Revocation is by exact signing identity or lowercase manifest SHA-256 in
  `revocations.toml` (append-only). It is signed by
  `.github/workflows/registry-pack-revocations.yml` and published to the
  `registry-pack-revocations` release; new documents are valid 36 hours. The
  repository-local `packs/revocations.json` feed is not the official root.
  The client reads the feed in `crates/mvm-core/src/registry_pack_revocation.rs`.
  Current `revocations.toml` lists no revoked identities or manifests.
- Older versions stay runnable by pin; each carries the policy it was signed
  with, and a new version never rewrites that policy.

### 4. What a pack never contains

- No secret values. Policy packs name bindings; application descriptors name
  logical slots (`ANTHROPIC_API_KEY`, required). The host endpoint substitutes
  credentials; the guest only sees placeholders.
- No guest NIC. Egress is the signed ceiling (`api.anthropic.com:443`) over the
  host-mediated channel, and requested permissions are not grants; admission
  and host policy decide (`CLAUDE-ENVIRONMENT.md`).
- No host credentials or host home mounts.
- No proprietary binary in git. Archives are release assets of this repository;
  git carries only the descriptor with the archive SHA-256, size and key ID.
  `pack-sources/agent/claude/environment-inputs.json` records an upstream
  archive and executable digest as input evidence only; it is not a
  descriptor and is outside the policy pack's payload
  (`docs/application-packages.md`).

### 5. Current state

- `agent/claude@1.0.1` (manifest SHA-256 `c4be773e...6293f5` in `index.json`)
  is policy only, with the profile above. All nine published packs are policy
  packs; `index.json` lists no application and no `agent/claude@2.0.0`.
- A runnable `agent/claude@2.0.0` aarch64 preview exists only as a draft
  (unpublished) release `pack-agent-claude-v2.0.0`. Its assets:
  `claude.mvmpkg` (456523776 bytes, SHA-256
  `cdbd8005dc356add632b3fce4ae19b7912e509df2d359e1d3b8786252de1a2b1`),
  `claude.mvmpkg.sha256`, `claude-bundle-publisher.pub` (public key, key ID
  `ada32b29ba81aa751cd16a3735be29e9`) and `claude-application.json`
  (descriptor evidence: entrypoint `/etc/mvm/entrypoint`, 2 vCPU, 4096 MiB,
  egress to `api.anthropic.com:443`, one required secret slot). The release
  text says Claude Code 2.1.273, while `environment-inputs.json` records
  2.1.312; the two are not reconciled here, and this ADR does not claim either
  is the version in the archive.
- Not verified: the archive's contents (not opened), any pull/install/run
  witness, a compatible signed `mvmctl` release, and permission to distribute
  the Claude binary. Redistribution permission is an operator assumption, not
  something this repository or its checks establish
  (`docs/application-packages.md`, `CLAUDE-ENVIRONMENT.md`).

### 6. Addendum: image-bearing packs and naming

- **A third shape exists in source.** `pack-sources/runtime/python` (1.1.0)
  carries `[image_build]` intent, and `README.packs.md` describes a generated
  `[image]` descriptor with a base-set pin and seven release assets. That is a
  built-image path, tracked in
  [#12](https://github.com/tinylabscom/mvm-packs/issues/12) and PS-06. The
  publisher defers it and `build-packs.py` refuses to publish an `[image]`, so
  nothing image-bearing is published and this ADR's two kinds still describe
  everything in the registry. If that path ships, it must either resolve to an
  application pack (a `.mvmpkg` pinned by a descriptor) or get its own ADR; it
  must not become a third way to embed software without one.
- **Name.** The PS-06 plan (`.claude/plans/ps06-oct20-completion.md`) calls the
  Claude pack `anthropic/claude`. This ADR, the draft release and the
  descriptor use `agent/claude@2.0.0`. No decision is recorded for the
  `anthropic/` namespace; ADR 002 proposes owner-based namespaces, under which
  the vendor name would belong to the vendor's own publisher entry. Until that
  is decided, `agent/claude` is the only name used here.
- **Applications are embedded in the `.mvmpkg`.** Every pack that is meant to
  run software (the other `agent/*` packs and the `runtime/*` packs are
  policy-only today) needs its own application version pinning such an
  archive. [#67](https://github.com/tinylabscom/mvm-packs/issues/67) tracks
  Codex, Goose and OpenCode.

## Policy composition

Sources, all in the `mvm` repository: `specs/prd.md` ("Composable"),
`public/src/content/docs/guides/policy-and-profiles.md` (merge rules),
`public/src/content/docs/guides/pack-authoring.md` ("What a pack cannot do"),
`specs/adrs/055-mvm-pack-naming-and-trust.md`, and the merge code and tests in
`crates/mvm-client/src/policy_profiles/` (`merge.rs`, `merge_tests.rs`,
`resolve_tests.rs`).

**Layers.** `specs/prd.md` lists: host constraints, organization policy, user
policy (groups and profiles), the signed pack and application, and the
invocation's flags. Referenced packs and groups are included by a pack's
profile `groups.include` (`pack-sources/agent/claude/pack/profile.toml` names
`llm-apis`, `github`, `runtime/python`). The admission ceiling is the host
budget and per-workload limits applied at admission (`specs/prd.md`, ADR-001
claim 18).

**Order.** Groups apply first; then each profile's `[[when]]` blocks and
`[overrides]`, parents before children; with repeated `--policy`, the last
entry takes precedence; flags are the last, most specific layer
(`policy-and-profiles.md`).

**Merge by field** (`policy-and-profiles.md`, "Merge rules"; the cited tests
are in `crates/mvm-client/src/policy_profiles/merge_tests.rs`):

| Field | Rule | Test |
| --- | --- | --- |
| Allow lists (hosts, env names, tools) | union | `allows_are_unioned_and_canonicalized` |
| Denies | union; a deny beats an allow from any layer | `a_deny_beats_an_allow_from_any_layer_in_either_order` |
| `network.block = true` | stays blocked; a later `false` is an error | `a_child_cannot_turn_the_network_back_on` |
| Secret bindings | a later layer may only narrow destination hosts | `a_later_layer_cannot_widen_a_secrets_destinations` |
| Resources | every bound is a ceiling; the smallest wins | `every_resource_bound_takes_the_smallest` |
| Shares | a pack cannot add a host share; writable only if every layer says so | `a_pack_cannot_add_or_modify_a_host_share` |
| `env.readmit` | honoured only in user-authored layers | `an_escape_hatch_outside_user_authored_layers_is_stripped_with_a_note` |

**Pack limits.** A pack cannot import local policy, use an escape hatch, mount
a host directory, undo a deny, or widen a stored secret's destinations
(`pack-authoring.md`). Its signed application ceiling binds the user and
cannot be widened locally (`policy-and-profiles.md`; `specs/prd.md` rule 4).
The user can narrow: flags such as `--secret NAME:HOSTS`, `--cpu-limit` and
`--timeout` apply only when tighter, and `--cpus`/`--memory` must fit the
ceilings. The user cannot widen a signed ceiling, and a flag cannot exceed a
resource ceiling. For applications, `specs/prd.md` states the effective
permission is the grant intersected with every layer's ceiling (rule 4); I
found no test cited for that exact sentence.

**Unresolved disagreements, reported not resolved.**

- `specs/prd.md` rule 3 says grants come only from host-owner layers and a
  pack's request grants nothing until a user layer grants it, and the PRD
  itself says it must still be verified that a pack's allowed network hosts
  are requests. The merge guide instead says allows are unioned and lists
  hosts, so a pack's hosts (for example `api.anthropic.com` through the
  `anthropic` binding) appear to add directly. ADR 055 says only secret
  bindings are requests. Which of these governs pack-authored egress hosts is
  not settled by the sources, and this ADR does not choose.
- The PRD lists the signed pack after user policy; the guide states only that
  later `--policy` entries win. Where the pack layer sits relative to user
  `--policy` entries for non-security choices is not stated in one place.
- Organization policy appears in the PRD layer list; I found no merge code or
  test for it, so it is intended, not shown as enforced.
- `specs/prd.md` says every rule has a test and `mvmctl policy show` names
  the deciding layer; I verified tests for the rows above only.

## Consumer workflow

The target experience is one page per pack, as a container registry lists an
image. Generated pages in `docs/registry/` list the published metadata and
policy content already in this repository; archive-only fields require a
verified pull. The client commands below remain the consumer workflow.

**Reference.** `namespace/name[@version]`. In the client, an unpinned
reference resolves to the highest published version in `index.json`
(`resolve_version` in `crates/mvm-cli/src/pack_registry.rs`). The literal
`latest` is not a version: it fails to parse as one (same file, test
`for version in [..., "latest"]`). Resolution does not consult revocation;
revocation is checked when the descriptor is installed and again at launch
(`application_bundle/launch.rs`). So "newest non-revoked" is the target; the
code today picks the highest published version and refuses it later if revoked.

**Commands, verified in the `mvm` tree.**

- `mvmctl search [QUERY] [--json]` exists (`crates/mvm-cli/src/commands/search.rs`).
  It lists name, description and published versions from `index.json`.
- `mvmctl pull ns/name[@version] [--json]` exists (`commands/pull.rs`). For an
  application it prints the reference, manifest digest and bundle SHA-256, and
  with `--json` the bundle key ID. `mvmctl pack pull <ref>` is the name
  `public/src/content/docs/reference/cli-commands.md` gives it.
- `mvmctl run ns/name[@version] -- <cmd>` exists for an installed application;
  `-a/--app/--application` takes the reference strictly. The same document
  shows `printf '%s\n' 'tell me a joke' | mvmctl run agent/claude` as the
  intended no-flag flow. Streaming stdin is documented as
  `machine run --entrypoint --stdin -`; whether the bare piped form works for
  a given pack was not exercised, and no published pack is runnable today
  (see Current state), so the flow cannot be run end to end.
- One-time setup (compatible client, publisher and bundle-key trust, revocation
  trust, a host-held provider key) is a prerequisite; running never enrolls
  trust.

**Each pack page must show**, derived only from existing bytes:

| Field | Source |
| --- | --- |
| Versions, manifest digest | `index.json` `versions[].version`, `manifest_sha256` |
| Bundle SHA-256, archive size, architecture | descriptor `application.bundle.archive_sha256`, `archive_size`, `guest_arch` |
| Pull and run snippet | the reference plus the commands above |
| Entrypoint, resources, egress ceiling, secret slots | the bundle's `EnvironmentDescriptor` (`entrypoint`, `resources`, `policy`, `secret_slots`) |
| Writable paths | `EnvironmentDescriptor.volumes`; empty means none declared |
| Publisher identity, key ID | workflow identity of `manifest.sigstore.json`; descriptor `bundle.key_id` |
| Revocation status | `revocations.toml` feed, by manifest SHA-256 and identity |

The bundle fields live inside the archive, so a page needs either the archive
or a `claude-application.json`-style evidence file beside it, which is not
signed registry metadata. A created date is not in the index, registry
manifest or descriptor; it exists only as `created_at` in the bundle manifest,
so a page may show it only after reading the archive.

**Compatibility.** The architecture column must equal the host's before a
run is offered. A pack is multi-architecture only if its descriptors cover
every architecture it claims; a descriptor holds one `guest_arch`, so
`agent/claude@2.0.0` is aarch64 only.

## Consequences

- A reader can tell a policy pack from a runnable one by `kind` and by the
  presence of `files/` versus `application`.
- Archive trust stays independent of registry trust, so a registry compromise
  cannot make an unenrolled bundle key trusted, at the cost of a one-time key
  enrollment by each consumer.
- Large archives stay out of git; availability depends on the release asset
  staying at its pinned digest.
- Policy-only packs stay available and unchanged after a runnable version ships.

## Follow-ups

- Publish `agent/claude@2.0.0` only through the manual publish dispatch that
  names a signed compatible `mvmctl` release, and only after the exact
  asset is read back and verified; this adds the index entry for 2.0.0.
- Public image publication and verification continue under
  [#12](https://github.com/tinylabscom/mvm-packs/issues/12).
- Record the distribution-permission decision in #31 before any public
  release. Nothing here is a claim of public release.
