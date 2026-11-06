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

## Status of the code

`scripts/application_manifest.py` validates the layer descriptor and the pins,
and `build-packs.py` refuses to sign a layer or an application that composes
layers until the gate exists. The legacy rule still holds: every pack ships a
binary.
