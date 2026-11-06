# ADR 003: Declaring and checking what an application pack embeds

Status: proposed; the pre-sign check is implemented for first-party sources in
`build-packs.py` (`scripts/rootfs_requirements.py`)
Date: 2026-11-06
Related: [ADR 001](001-pack-contents.md), [ADR 002](002-third-party-publishing.md)

## Purpose

An application pack must carry the application and every utility it needs, so it
runs from the `.mvmpkg` alone, with no package install at start and no tools
assumed on the host. ADR 001 puts the software in the archive; this ADR adds a
way to say what "everything it needs" is and to check it before the registry
signs the descriptor.

The `[requirements]` check is implemented for first-party sources. No published
pack declares requirements yet, because no application pack is published.

## Context: what the registry can check today

Before signing, `build-packs.py` verifies the archive's digest and size, that it
holds a kernel and a root filesystem whose hashes match the bundle manifest, the
descriptor's key ID and architecture, and the Ed25519 `manifest.sig`. It never
looks inside the root filesystem, so an archive that omits a needed tool passes.

The draft `agent/claude@2.0.0` archive (read with `debugfs`, read-only, on
2026-11-06) has a Nix-closure root filesystem of 18 store paths:
`claude-code-native-2.1.273`, `mvm-agent`, `bash-5.3p3`, `coreutils-9.8`,
`busybox-static`, `glibc-2.40`, `musl-1.2.5`, gcc runtime libraries, `acl`,
`attr`, `gmp`, `libidn2`, `libunistring`, `mvm-setpriv-static` and two mvm
helper trees. The entrypoint runs `mvm-agent --allowedTools WebFetch
--max-turns 3 --max-budget-usd 0.50` under that bash. There is no `git`,
`ripgrep`, `curl`, `node`, `python3` or `jq`.

What Claude Code needs, from its setup page (2026-11-06): a shell (Bash, Zsh,
PowerShell or CMD); ripgrep, "usually included" and bundled except on musl
systems, where it must be installed and `USE_BUILTIN_RIPGREP=0` set; git is
optional (only some commands need 2.31 or later); on musl, `libgcc`, `libstdc++`
and `bash`. So this demo archive is plausibly complete for its restricted
purpose, and incomplete for a general coding environment, which would want `git`
at least. That is a product decision, not something this ADR settles.

## Decision

### 1. Requirements are declared beside the source, unsigned

An application source may add a `[requirements]` table to its `pack.toml`:

```toml
[requirements]
packages = ["claude-code-native", "mvm-agent", "bash", "coreutils", "musl"]
commands = ["bash", "sh"]

[[requirements.binaries]]
package = "claude-code-native"
path = "bin/claude"
sha256 = "7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1"
size = 221263520
```

- `packages`: Nix store package names without hash or version. Each must appear
  as `/nix/store/<hash>-<name>-<version>` in the root filesystem.
- `commands`: executable names that must resolve to a regular executable file or
  symlink in `/bin`, `/usr/bin`, `/usr/local/bin` or a store package's `bin/`.
- `binaries`: pins the application's own executable. Each entry is `package`,
  `path` (relative to the store directory, for example `bin/claude`), `sha256` and
  `size`. The check dumps that file from every store directory of the package and
  refuses unless the bytes match exactly. A name-only check would accept any
  program installed under the right name; a pin does not.

`[requirements]` is registry-side build input. It is not in the signed descriptor,
whose five fields and nested application schema are shared with the client and
stay unchanged. It states what the publisher claims the archive contains; the
check makes that claim true at signing time. It does not bind the archive to the
list afterwards.

### 2. The check reads the root filesystem without mounting it

The publisher already spools the archive to disk. It extracts only the
`rootfs` artifact (a member already hash-checked against the bundle manifest) to
a temporary file and lists it with `debugfs -R` from `e2fsprogs` (read-only; no
mount, no root, no code from the image runs). It refuses unless every declared
package and command is found. The validate workflow already installs
`e2fsprogs`; the publish and intake workflows would add it.

Limits: it supports the Nix-store layout of mvm-built roots; any other layout
fails closed when requirements are declared. It proves presence, not that the
package works or is the right version, and not that the binary is unmodified
(for Claude Code 2.1.273, about 64% of sampled bytes match the official release,
so this ADR does not claim byte identity).

Safeguards on the check (from the `mvm` client team's review):

- It runs on the exact rootfs bytes whose digest chains to the signed descriptor:
  the member is read from the already digest-checked archive and hash-checked
  against the bundle manifest, never from a rebuilt copy.
- `debugfs` is invoked read-only with `-R`, with a time limit and an output size
  limit, and its output is treated as untrusted text (never interpreted, escaped
  when printed).
- The table is not authority and changes nothing the client trusts.

### 3. Claude's list

For `agent/claude@2.0.0` as built: packages `claude-code-native`, `mvm-agent`,
`bash`, `coreutils`; commands `bash`, `sh`; and one binary pin for
`claude-code-native` `bin/claude` (SHA-256 and size below).

Correction: an earlier draft of this ADR said the embedded Claude binary is
glibc-linked, so its bundled ripgrep applies. That was taken from the 2.1.312
pin file, not from the archive, and it is wrong. The embedded binary uses the
**musl** loader (see Evidence). The vendor's setup page says musl builds need a
system `ripgrep` with `USE_BUILTIN_RIPGREP=0`, and `libgcc`, `libstdc++` and
`bash`. The closure has the gcc libraries and bash and has no `ripgrep`, so
search tools are probably unavailable in this archive; the web-fetch-only demo
does not use them. This is unconfirmed until the boot test runs.

Keep this pack minimal: the demo contract (`tinylabscom/mvm#4839`, one WebFetch
over 3 turns) needs no `git` or `rg`. A coding-agent use needs more (at least
`git`), which belongs in a separate variant pack with its own version and
digest, not in a larger default; the descriptor never changes after signing.
Tools are not added speculatively (`curl`, `node`, `python3`, `jq`): each one is
attack surface in a sealed root filesystem and enlarges the signed digest.

The right list for a workload is found empirically: boot the draft rootfs through
the builder/consumer path, run the intended workload class, and record which
commands fail with "not found". Until that is done the list above is the
minimum, not a proven sufficient set.

### 4. Community packs

A community author has no source in this repository, so `[requirements]` cannot
sit in our `pack.toml`. Two options for the owners to choose: keep community
packs unchecked for contents (the intake already checks signature, kernel,
rootfs and hashes), or add an optional `requirements` list to the community
reference file, checked by intake the same way. The second is more consistent;
it is not decided here.

## Evidence: what is embedded (read from the draft archive, 2026-11-06)

The embedded `claude` (`/nix/store/…-claude-code-native-2.1.273/bin/claude`) is
the official **musl** build of Claude Code 2.1.273 with its ELF headers rewritten
by a patcher:

- Embedded file: 221263520 bytes, SHA-256
  `7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1`; loader
  `/nix/store/…-musl-1.2.5/lib/ld-musl-aarch64.so.1`.
- Upstream `claude-linux-arm64-musl.tar.gz` (v2.1.273): SHA-256
  `ebf9f42fe97219969f7bcbd89460b57a177dd1bd26b4b25e9458cfbc9ecb4528`; its binary
  is 221197984 bytes, SHA-256
  `0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6`, loader
  `/lib/ld-musl-aarch64.so.1`.
- The embedded file is 65536 bytes larger. `scripts/compare-patched-elf.py` checks,
  rather than assumes, that it is the upstream file plus a loader-path patch, and
  exits non-zero otherwise. Against the real pair it verifies that: the ELF header
  is unchanged except one more program header and the section table moved by
  exactly the shift; every upstream program header reappears unchanged with its
  file offset moved by exactly the shift; the one extra header is a new
  **writable, non-executable** `PT_LOAD` (flags RW) of 64 KiB inside the inserted
  bytes, adjacent to and not overlapping any upstream segment, holding the new
  program header table and the new loader string; everything else in the inserted
  bytes is zero; the old ELF header and program header table are zeroed and the
  old loader string is overwritten with `X` filler; every section matches by name
  with only its file offset shifted (`.interp` moved to the new segment); and all
  other bytes of the 221 MB body are identical, except 7 one-byte `.dynsym`
  section-index fields that name the same section in both files. Nine tampering
  attempts on the real pair (a flipped bit in the code, a changed entry point, an
  executable new segment, a nonzero padding byte, a changed section address, an
  unrelated `.dynsym` byte, extra bytes in the old loader area, a shrunk segment)
  are each refused. The new loader is
  `/nix/store/…-musl-1.2.5/lib/ld-musl-aarch64.so.1`.
  Limits: the comparison itself is only exercised against this real pair (no
  synthetic ELF fixtures), and a writable header segment is the patcher's design,
  not something this repository can remove.
- The upstream tarball is authentic as far as the vendor's own signature goes:
  `SHASUMS256.txt` for v2.1.273 verifies with `gpg` ("Good signature from
  Anthropic Claude Code Release Signing") against a key whose fingerprint
  `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE` is the one the vendor's
  setup page publishes, and its `claude-linux-arm64-musl.tar.gz` line equals the
  tarball hash above. Checked 2026-11-06 in a throwaway keyring; the key was
  fetched from the vendor's site, so this trusts that site and the setup page
  together, not an independent channel.
- `docs/claude-environment-inputs.json` (moved out of the source directory, which
  may hold only `pack.toml`) records a different build (2.1.312, glibc). It does
  not describe this archive.

## Consequences

- A pack declares what it needs and the registry refuses to sign one that lacks
  it, which closes the "boots but useless" gap for first-party packs.
- No change to the descriptor or the client.
- The publish path gains a dependency on `debugfs` and a temporary copy of the
  rootfs (about 400 MB for Claude).
- The list is only as good as its author; it does not catch a tool needed by a
  code path nobody listed.

## Open questions

- Whether to ship a separate coding variant of `agent/claude`, and who runs the
  empirical boot test that finds its missing commands. The product owner decides.
- Whether `commands` should also check that the file is executable and for the
  right architecture (`debugfs` can read mode and an ELF header via `dump`).
- Whether to verify the Sigstore sidecar bundles in the archive, which needs
  their signing identities recorded somewhere.
