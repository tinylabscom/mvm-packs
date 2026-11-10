# Draft portable application component descriptor

**Registry-side candidate only. Not publishable or supported by `mvmctl`.**
ADRs [004](adr/004-mvmpkg-universal-pack.md)–[006](adr/006-runnable-composable-packs.md)
require a new application-only format; the `mvm` composable-build contract
does not yet specify its exact wire fields. This is a reviewable proposed
registry shape, **not an agreed wire format**. Coordinate the names, ABI and
capability vocabulary, payload tar format and caps with the `mvm` format owner
before enabling publication or consumer dispatch. `build-packs.py` rejects
these sources even with `--check-sources`, and signs nothing.

The closed outer manifest uses `schema_version: 3`,
`kind: "application_component"`, an exact
`namespace/name@major.minor.patch` reference, nonempty description,
`application_component` (schema 1), and `files`. One version targets one
`guest_arch` (`aarch64` or `x86_64`). The component's `archive` binds a canonical
HTTPS or digest-pinned OCI source, lowercase SHA-256 and positive byte length
at most 2 GiB. There is **no archive key ID or second signer**: the eventual
keyless-signed registry descriptor authenticates the payload pin, and a
consumer must hash the exact archive bytes before use. Neither a descriptor
nor a capability request grants host authority.

The signed `files` inventory holds one or both policy documents
`pack/group.toml`, `pack/profile.toml`, each with lowercase SHA-256 and positive
byte length; the application archive stays external. `requirements` declares
filesystem ABI 1, libc (`static`, `musl`, or `glibc`), absolute loader path for
dynamic libc (absent for static), minimum kernel `major.minor.patch` and up to
16 unique capability names. These declarations are requirements to compare
against a selected signed base, not evidence that it provides them.
`entrypoints` contains up to 16 uniquely named literal argv arrays, each
starting with an absolute executable. The entry named `default`, when present,
is the candidate default; other names are explicit-only commands. Runtime
overrides and explicit workload commands take precedence, then the last
application in explicit order with a `default` command (ADR 006). No kernel,
rootfs, initramfs, launch grant or install script is part of this descriptor.

Example source shape (all pins and bytes below are illustrative only):

```toml
version = "3.0.0"
description = "Example portable application"

[application_component]
schema_version = 1
guest_arch = "aarch64"

[application_component.archive]
source = "https://example.com/app.tar"
archive_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
archive_size = 123

[application_component.requirements]
filesystem_abi = 1
libc = "musl"
loader = "/lib/ld-musl-aarch64.so.1"
minimum_kernel = "6.1.0"
required_capabilities = ["pty"]

[[application_component.entrypoints]]
name = "default"
argv = ["/usr/bin/python3", "/srv/app/main.py"]
```

Only parser/renderer and registry-manifest structural validation are staged.
There is no archive read-back/extraction gate, compatible consumer, selected
base admission, protected signer or publication authorization. Existing
schema-1 policy and schema-2 complete `.mvmpkg` application bytes, v1
authoring, bundle signatures and release paths are untouched.
