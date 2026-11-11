# ADR 005: Runtime layers

Status: proposed. Registry-side descriptor parser exists; compatible
selectable-base consumer, admission and protected publication are not released,
so nothing described here can be published yet.

## Context

`runtime/*` packs (Python, Node, ...) are reusable, version-pinned software and
policy that compose with a portable application and a separately selected
bootable base into one VM. The existing schema-2 application descriptor and
`.mvmpkg` describe a complete bootable workload (kernel and rootfs); they
retain that meaning. A new versioned application component (ADR 004)
contributes application bytes without either boot asset.

## Decision

Follows the closed wire shape in the `mvm` contract (`specs/contracts/composable-pack-build.md`):

- **Layer manifest:** outer `schema_version = 3`, `kind = "runtime_layer"`, an exact
  `runtime/name@major.minor.patch` reference, a description, and
  `runtime_layer{schema_version = 1, guest_arch, dependencies, archive}`. `archive` is
  `{source, archive_sha256, archive_size}` with `source` a canonical HTTPS URL or a
  digest-pinned `oci://` reference and the size at most 2 GiB, the same pattern as an
  application descriptor's bundle, minus any key. The signed `files` inventory holds only
  `pack/group.toml` and/or `pack/profile.toml` (the policy), each with a digest and a positive
  size. No kernel, no entrypoint, no other file, no unknown field. The layer bytes live outside
  git; the consumer snapshots and hashes them before unpacking.
- **Dependencies:** an ordered list of at most 16 exact, manifest-digest-pinned `runtime/*`
  layers. A digest pin makes a cycle impossible; self and duplicate dependencies are refused.
- **No second signer:** the Sigstore-signed registry manifest binds the layer archive by digest
  and size. The layer has no key of its own.
- **Application descriptor versioned:** existing schema-2 boot-bundle descriptors
  remain unchanged. A new component kind/schema binds application bytes and
  compatibility requirements without boot assets. A separately protected,
  self-contained production `.mvmpkg` records the ordered component pins and
  selected base in signed provenance so later revocations can refuse derived bundles.
- **Policy:** composed by field with the existing rules: allows union, denies win, ceilings
  take the minimum, secret destinations only narrow, then intersected with host grants at
  admission (`tests/policy-vectors/`). A layer never grants itself access.

**Architecture:** one `guest_arch` per version, as for applications. Multi-architecture
fan-out under one version (M7) is left to a separate, versioned schema decision rather than
changing schema 3 now.

## Signature and trust

Every pack needs a verified signature to run. A composed pack is new bytes, so the
layers' signatures do not stand in for it.

1. A layer has one publisher signature: the keyless-signed registry descriptor
   binds its archive digest, size, architecture, dependencies and policy files.
   The external archive has no Ed25519 signature or `key_id`. Authenticate the
   publisher and descriptor, then verify the exact archive bytes before unpacking.
   A layer can be revoked by its manifest identity.
2. Existing published complete application `.mvmpkg` files retain their own
   independently trusted bundle signatures and registry pins. A future
   portable application component uses its versioned authenticated descriptor
   and digest-bound payload, not the signature of a different boot bundle.
   Protected production export signs the complete selected boot closure and
   binds ordered layer manifests, base evidence, policy and actual entrypoint.
3. A locally assembled ext4/verity result is not a publisher-signed pack. Its
   measured output and pinned inputs belong in a device-scoped authenticated
   receipt/plan (ADR 006), not in an invented publisher signature or registry
   descriptor. Admission must recheck every input's publisher trust and fresh
   revocation status, as well as host grants, even on a cache hit. Until that
   client and admission path exists, schema 3 remains unpublishable.

Development results must be visibly local and cannot be indexed or promoted by
relabelling. Production publication requires separate protected verification,
signing and approval; a local build or receipt never qualifies as an official
release.

## Entrypoint

Layers cannot set an entrypoint. An explicit runtime command override takes
precedence over a user-defined workload/config command, which takes precedence
over the last application in explicit order that declares an entrypoint.
Earlier applications keep theirs as named non-default commands; no service
starts unless explicitly requested. The actual selected command is admitted
against the security profile and host grants (even in production) and bound
to the signed plan/audit. Policy still composes across every component.

## Status of the code

`scripts/application_manifest.py` validates the closed `runtime_layer` shape, its archive pin and its
policy-file inventory and can render the manifest bytes; `build-packs.py` refuses to publish a runtime
layer until the `mvm` consumer dispatch, installer and our gate exist. `validate-packs.py`
accepts schema versions 1 to 4 but has no schema for a runtime layer, and signing refuses one, so a published layer fails closed. The legacy
rule holds: every pack ships a binary.
