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

- **Layer descriptor:** schema 2, `kind = "layer"`, field `layer` with the same
  `guest_arch` and `bundle{source, archive_sha256, archive_size, key_id}` pins
  as an application. It pins a typed layer archive: payload files and a policy
  member, with no kernel, no rootfs and no entrypoint. A layer cannot compose
  other layers.
- **Application descriptor:** gains an optional, ordered
  `application.layers = [{reference, manifest_sha256}]` of exact
  `namespace/name@major.minor.patch` pins (at most 16, no duplicates). The
  application still pins one final, self-contained `.mvmpkg` that carries the
  layer bytes, so a recipient needs no layer cache.
- **Policy:** composed by field with the existing rules: allows union, denies
  win, ceilings take the minimum, secret destinations only narrow. The result
  is intersected with host grants and signed application ceilings at admission
  (`tests/policy-vectors/`). A layer never grants itself access and cannot
  introduce an entrypoint.
- **Gate (to be built with the layer format):** the final archive's provenance
  must list each layer's reference and manifest digest equal to the pins, in
  order. Refuse a revoked or duplicate layer, an architecture mismatch, a second
  entrypoint, an overlapping path without a reviewed ownership rule, or a changed
  digest.

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

`scripts/application_manifest.py` validates the layer descriptor and the pins,
and `build-packs.py` refuses to sign a layer or an application that composes
layers until the gate exists. The legacy rule still holds: every pack ships a
binary.
