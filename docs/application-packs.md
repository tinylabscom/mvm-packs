# Publishing a legacy complete-bundle application pack

This guide describes the existing schema-2 application descriptor and
complete bootable `.mvmpkg`, **not** the proposed portable application-only
component ([ADR 004](adr/004-mvmpkg-universal-pack.md)). Its current
derive-pins and publisher checks require a kernel and rootfs and must not be
weakened to accommodate a new format. The portable authoring and protected
export path are not released; `mvmctl pack publish ./my-pack` remains a
proposal.

An application pack ships software, not just policy. It is two things bound together:
a small **descriptor** in this registry, and a **`.mvmpkg` archive** that holds the
software. This guide is for the person preparing the registry side. The archive itself
is built by the `mvm` toolchain.

## What gets signed, and by whom

| Object | Pinned by | Authenticated by |
| --- | --- | --- |
| Registry descriptor (`manifest.json`, schema 2) | `manifest_sha256` in `index.json` | Keyless signature by the publish workflow |
| The `.mvmpkg` archive | `archive_sha256` and `archive_size` in the descriptor | Its own Ed25519 `manifest.sig`, by the key named in `key_id` |

Two roots, and neither replaces the other. The descriptor does not make the archive's
key trusted; each consumer enrolls the key themselves. The signature in the archive and
the digest in the descriptor are checked **by the publisher before it signs anything**
(below).

## What the archive must contain

An **uncompressed tar** (compression is refused) with only regular files:

- `manifest.json` (canonical JSON, at most 1 MiB), with `key_id`, `arch` and a list of
  `artifacts`, each with `path`, `role`, `sha256` and `size_bytes`;
- `manifest.sig`: exactly 64 bytes, an Ed25519 signature over the exact bytes of
  `manifest.json`;
- `artifacts/...`: every listed artifact, including a `kernel` and a `rootfs`;
- one `environment` member in the manifest carrying the signed policy.

The Ed25519 public key (32 bytes) is published **beside the archive** as
`<archive stem>-bundle-publisher.pub`, for example `claude.mvmpkg` and
`claude-bundle-publisher.pub`. Its SHA-256, first 32 hex characters, must equal the
`key_id`. The key is never read from inside the archive.

## The source: one file

`pack-sources/<namespace>/<name>/pack.toml`, and **nothing else in that directory**. A
second file there makes the build fail.

```toml
version = "2.0.0"
description = "What the application is for."

[application]
schema_version = 1
guest_arch = "aarch64"

[application.bundle]
source = "https://github.com/OWNER/REPO/releases/download/TAG/app.mvmpkg"
archive_sha256 = "<64 hex>"
archive_size = 456523776
key_id = "<32 hex>"

[requirements]                       # unsigned build input, checked before signing (ADR 003)
packages = ["tool", "bash"]
commands = ["bash", "sh"]

[[requirements.binaries]]            # the application's own executable, pinned exactly
package = "tool"
path = "bin/tool"
sha256 = "<64 hex>"
size = 123

[requirements.environment_policy]    # the signed environment must carry exactly this
allow_hosts = ["api.example.com:443"]
```

`source` must be a canonical HTTPS URL or a digest-pinned `oci://host/repo@sha256:` reference.

## Derive the pins, do not type them

Download the archive and its key into their own empty directory, then:

```sh
python3 scripts/derive-pack-pins.py app.mvmpkg --key app-bundle-publisher.pub \
  --source https://.../app.mvmpkg --binary tool:bin/tool \
  --require-package tool --require-package bash --require-command bash \
  --environment-policy policy.json --show-file /etc/mvm/entrypoint
```

It measures the archive, runs the same checks the publisher runs, verifies each named
requirement against the real root filesystem, and prints draft blocks to review and
paste. It signs nothing and writes no file. `--show-file` prints a small file from the
root filesystem (for example the entrypoint wrapper) with its hash, for review.

## What the publisher checks before signing a new version

Digest and size equal the descriptor; every tar member is a safe regular file; the
manifest's `key_id` and `arch` equal the descriptor's; every artifact is present with its
recorded hash and size, none listed twice, and a kernel and rootfs exist; `manifest.sig`
verifies; each declared package, command and binary pin is present in the root filesystem
(by inode, read-only, nothing executed); the signed environment policy equals the declared
one exactly. Anything else fails the build, and no manifest is signed.

## What readers see

When the publisher signs a new application version it also writes
`pack-details/<namespace>/<name>/<version>.json`: the architecture, creation time, runtime
asset versions, artifact hashes, the signed environment (entrypoint, resources, policy, secret
slots, capabilities) and the pinned executables it saw in the archive. The pack page shows
this under "Recorded at signing", labelled as **not signed registry metadata**. `validate-packs`
refuses a record that does not match the signed descriptor. A failure to write the record never
blocks signing, and a pull re-verifies the archive itself.

## Per-architecture versions (provisional)

**Provisional; not yet confirmed with the `mvm` owner.** One descriptor targets one
`guest_arch`, a published version is immutable so two descriptors cannot share a version,
and the `mvm` client filters versions by host architecture and then takes the highest
semver (`resolve_matching` in `discovery.rs` in the `mvm` repo). The proposed scheme: within
one release line the aarch64 build takes `X.Y.0` and the x86_64 build takes `X.Y.1`; a new
release line bumps the minor. This needs confirmation by the `mvm` owner. If they choose a
different scheme, only the version numbers in the pack sources and these docs change.

## Traps we have already hit

- **A draft release cannot be read.** The publisher downloads anonymously. Merging a
  descriptor whose release is still a draft fails the build, which also blocks the
  revocation refresh that runs in the same step. Make the release public first.
- **A rebuilt archive is a different archive.** New digest, size, often a new key and a new
  binary hash. Every pin must be redone and the new archive approved; do not edit one field.
- **Archives are not recompressed.** Compression changes the digest and is refused.
- **The binary pin needs one store directory.** If two versions of a package are present,
  the tool refuses to guess.
- **Patched executables.** A loader-patched binary differs from upstream. Pin the embedded
  bytes, and record how it relates to upstream (ADR 003 evidence and
  `scripts/compare-patched-elf.py`).
- **Do not set `USE_BUILTIN_RIPGREP=0`** for a standalone Claude Code binary: it carries its
  own ripgrep and the variable forces a system one.
- **Shell and libc go together.** A glibc `bash` needs the glibc loader in the closure.
- **Local files are refused.** `file://` sources are rejected by design, so the first real
  pull is only possible after publication.
- **A published version never changes.** Change the source and the version must change.
- **Signing and publishing need separate approval** from the maintainer for the specific
  archive, apart from a green CI run.

## Acceptance: assert a value, not a boot

A pack that lost its root filesystem can still boot and exit zero. The boot test should read a
known value from inside the running artifact (for example the exact version string and one
search result) and compare it, not only observe a clean start.
