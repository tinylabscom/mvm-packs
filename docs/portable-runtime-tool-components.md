# Draft portable runtime and tool component descriptors

**Registry-side candidate only: not publishable, signed, or supported for
launch.** This proposed schema-4 contract preserves the separate schema-3
`runtime_layer` and `application_component` candidates and every published
schema-1/2 version. The exact ABI, archive rules and capability vocabulary
still require consumer conformance, archive/ABI admission and boot witnesses
before any production publication. `build-packs.py` refuses these sources,
including `--check-sources`; `validate-packs.py` checks the candidate manifest
shape only, not publisher trust, archive contents or base compatibility by
default.

The outer signed descriptor has **exactly** `schema_version: 4`,
`kind: "runtime_component"` or `"tool_component"`, a matching
`runtime/name@major.minor.patch` or `tool/name@major.minor.patch` `reference`,
nonempty `description`, the same-named nested component and `files`.
Each nested component has **exactly** `schema_version: 1`, `guest_arch`
(`x86_64` or `aarch64`), `requirements`, `dependencies` and `archive`.
`requirements` is the application component's closed shape: integer
`filesystem_abi = 1`, `libc` (`static`, `musl`, `glibc`), canonical absolute
`loader` iff libc is dynamic, `minimum_kernel` as `major.minor.patch`, and
at most 16 distinct canonical `required_capabilities`. These are *requirements*
to compare against a selected signed base, not grants.

`dependencies` is an ordered list of at most 16 exact `runtime/*` or `tool/*`
version references, each pinned by lowercase `manifest_sha256`; duplicate
namespace/name or self-dependency is invalid. The consumer must resolve the
full graph and check cycles; direct-pin validation alone is insufficient.
`archive` has only `source` (canonical HTTPS or digest-pinned OCI),
`archive_sha256` (lowercase SHA-256), and `archive_size` (positive, at most
2 GiB). There is **no second archive signer or key ID**: the eventual verified
keyless registry signature binds the archive pin, and the consumer must hash
the exact fetched bytes before extraction. `files` inventories only one or
both `pack/group.toml` and `pack/profile.toml`, each with SHA-256 and positive
byte size; the archive remains external. No entrypoint, kernel, rootfs,
initramfs, install script or independent launch authority is declared.

Example proposed source for `pack-sources/runtime/demo/pack.toml` (illustrative
pins only; there is no release):

```toml
version = "1.0.0"
description = "Example runtime component"

[runtime_component]
schema_version = 1
guest_arch = "aarch64"
dependencies = [{ reference = "tool/helper@1.2.3", manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[runtime_component.archive]
source = "https://example.com/runtime.tar"
archive_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
archive_size = 123

[runtime_component.requirements]
filesystem_abi = 1
libc = "musl"
loader = "/lib/ld-musl-aarch64.so.1"
minimum_kernel = "6.1.0"
required_capabilities = ["pty"]
```

For a tool, use `pack-sources/tool/demo/pack.toml` and replace every
`runtime_component` table name with `tool_component`; both component kinds
use the same nested contract. A future signed manifest would contain the
policy-file inventory alongside the nested component, not embedded in it.
