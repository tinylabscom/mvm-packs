# ADR 005: Runtime layers

Status: proposed. Registry-side descriptor shape only; the layer archive format
and its gate belong to the `mvm` bundle work and are not implemented, so
nothing described here can be published yet.

## Context

`runtime/*` packs (Python, Node, ...) are reusable, version-pinned software and
policy that compose with an application into one VM with one entrypoint. The
application descriptor and `.mvmpkg` describe a complete bootable workload (a
kernel, a rootfs, an entrypoint), so they cannot double as a layer.

## Decision

Follows the closed wire shape in the `mvm` contract (`specs/contracts/composable-pack-build.md`):

- **Layer manifest:** outer `schema_version = 3`, `kind = "runtime_layer"`, an exact
  `runtime/name@major.minor.patch` reference, a description,
  `runtime_layer{schema_version = 1, guest_arch, dependencies}`, and a signed `files`
  inventory of `layer.tar` (at most 2 GiB) plus at least one of `pack/group.toml` or
  `pack/profile.toml`, each with a digest and a positive size. No kernel, no entrypoint,
  no other file, no unknown field.
- **Dependencies:** an ordered list of at most 16 exact, manifest-digest-pinned `runtime/*`
  layers. A digest pin makes a cycle impossible; self and duplicate dependencies are refused.
- **No second signer:** the Sigstore-signed registry manifest authenticates `layer.tar` by
  digest. The layer has no key of its own.
- **Application descriptor unchanged:** the final self-contained `.mvmpkg` records the input
  runtime manifest pins in its signed provenance, so a later layer revocation can refuse
  derived bundles. The registry application descriptor gains no field.
- **Policy:** composed by field with the existing rules: allows union, denies win, ceilings
  take the minimum, secret destinations only narrow, then intersected with host grants at
  admission (`tests/policy-vectors/`). A layer never grants itself access.

**Open constraints, raised with the `mvm` owner:** a layer tar under the registry `files/` tree
means git-hosted bytes (GitHub rejects files over 100 MB), and one `guest_arch` per manifest
means one architecture per version. A hosted `source` and per-architecture entries would
avoid both; neither is in the wire shape yet.

## Signature and trust

Every pack needs a verified signature to run. A composed pack is new bytes, so the
layers' signatures do not stand in for it.

1. Each layer is signed on its own: a keyless-signed descriptor, and an Ed25519
   bundle signature on the layer archive pinned by `key_id`. Each can be revoked
   individually.
2. The assembled `.mvmpkg` carries its own in-file signature over its final bytes
   (ADR 004).
3. That signature covers a provenance member: the ordered layers (reference,
   manifest digest, signer), the composed-policy digest, the entrypoint owner and
   the trust class.
4. The registry descriptor pins the final archive; the publisher gate checks the
   signature and that the provenance layer digests equal the descriptor pins.
5. Admission re-checks at run time: it verifies the final signature against a
   trusted key and every provenance layer digest against the revocation feed (a
   layer revoked after assembly stops the pack), then intersects the composed
   policy with host grants.

Two trust classes live inside the signed provenance:

- **dev** (default): signed with a local key generated on first use. The host
  trusts that key for the dev class only, on that machine. A dev pack shows a dev
  marker and cannot be published, used as a layer in a production build, or
  indexed.
- **production** (explicit, for example `pack build --production`): refuses to
  start unless every input is pinned to an exact digest, registry-signed and
  unrevoked, and it builds from the lock. It is signed with a publisher key the
  host has explicitly trusted; the auto-generated dev key never qualifies.
- Promotion is a rebuild. The class is inside the signature, so a dev archive cannot
  be relabelled production.
- Official remains a separate tier: only our keyless publish workflow.

## Entrypoint

Only an application owns the entrypoint; layers cannot set one. When several
applications are stacked, the last in the locked order owns the entrypoint, earlier
applications keep theirs as named non-default commands, and provenance records the
owner and the shadowed entrypoints. Policy still composes across all of them.

## Status of the code

`scripts/application_manifest.py` validates the closed `runtime_layer` shape and its file
inventory and can render the manifest bytes; `build-packs.py` refuses to publish a runtime
layer until the `mvm` consumer dispatch, installer and our gate exist. `validate-packs.py`
still accepts only schema versions 1 and 2, so a published layer fails closed. The legacy
rule holds: every pack ships a binary.
