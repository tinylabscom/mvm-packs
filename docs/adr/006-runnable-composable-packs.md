# ADR 006: One-command runs from a selected base and signed components

Status: proposed contract; candidate implementation is not a release
Date: 2026-11-10
Related: [ADR 004](004-mvmpkg-universal-pack.md),
[ADR 005](005-runtime-layers.md), [application pack guide](../application-packs.md);
`mvm` `specs/contracts/composable-pack-build.md`

## Product contract

`mvmctl run agent/claude` remains one command with a fast compatible default:
authenticate/acquire the app and signed default boot inputs, admit, and
launch; the user's first run must not build Nix or fetch dependencies in the
guest. An explicit ordered composition with a selected custom base is also
one command. The same portable application bytes work with any base that
meets the declared compatibility contract. Existing published
`agent/claude@2.0.1` is a **complete boot bundle**, not that portable
component, and keeps its existing reader and meaning; the legacy `.mvmpkg` wording stays true
for the published 2.0.x packs, which are immutable and unchanged.

Packs carry the application, its policy and its requirements, and **no
base** (no kernel, rootfs or backend). **Provisional; to be confirmed with
the `mvm` thread:** a fallback base supplied by `mvm` is acceptable only when
the user names none; it must come from `mvm`, never from a pack, and a
user-chosen base always wins.

The signed base evidence must identify the architecture, kernel and
initramfs, composition filesystem input and verified guest runtime,
including digest/size, filesystem ABI and minimum kernel features.
Application and runtime requirements state their target architecture,
supported ABI/libc and loader, minimum kernel and required capabilities.
The resolver checks these against the selected base, not against an
assumed default. A development base can use local measured evidence;
production requires an independently trusted, signed base and guest
runtime. Missing/unknown fields, untrusted evidence or mismatch fail
closed, without a different-base retry.

Resolve an **explicitly ordered** graph of exact-version,
manifest-digest-pinned, publisher-authenticated application/runtime/tool
components. Dependencies are pinned and cycle/duplicate checked; the
resolved order is recorded. Snapshot every payload and signed policy
document before use. Reject unsafe archive entries, special files,
symlink escapes, ownership or permission changes, collisions with
base-owned paths, and any duplicate path between components. No
last-wins file overwrite, whiteout, automatic install script or guest
network fallback is allowed.

Entrypoint precedence is: runtime command override, then the
user-defined workload/config command, then the **last application in
the explicit order that declares a `default` entrypoint**. "Last wins" applies to command selection only, and the chosen command
is separately admitted. Other applications' commands remain
non-default and services do not auto-start; a service requires an
explicit request. A runtime override, including in production, is
checked against the selected security profile, signed component
ceiling and host-authorized grants. Bind and audit the **actual**
command that executed, not only an earlier default or declared argv.
The host grants no network, secret or share merely because a pack
requests one. Denies prevail, ceilings narrow, and policy composition
must have one authoritative tested implementation.

No guest NIC, NAT, SSH or networking fallback is introduced. Any
permitted networking remains host-mediated over authenticated
FlowMux/vsock.

## Assembly, cache and admission

Assemble and measure one ext4/verity workload **before first boot**.
Use one cache key over the exact selected base and runtime identities,
ordered component payload digests and filesystem ABI, and assembler
version. A cached output must be rehashed/verity-verified before use.
Policy, grants and selected command are **not** filesystem inputs:
changing only the admitted command must not rebuild unchanged bytes.
If a producer bakes command or policy bytes into the filesystem, those
bytes are instead explicit hashed assembly inputs and invalidate the key.
Keep actual transfer bytes, retained disk and cold assembly/boot versus
repeat boot times as separate metrics.

The existing host-signed local bundle/schema-8 inventory, signed plan
and host admission path are the starting point, **not** a parallel
composer or second cache. Bind selected base evidence, guest runtime,
ordered component manifests and policy hashes, ext4/verity output,
effective policy, command choice and launch command. On *every* run
and immediately before launch, recheck publisher trust, fresh
rollback-protected revocation feeds for all inputs, filesystem
measurement, effective policy and host grants. Missing, stale, revoked
or rolled-back evidence refuses launch, even after a cache hit.

A local result carries a development trust class; host signing is not
official publisher authority. Production export is a separately
protected, independently verified and signed single `.mvmpkg` with
its entire boot closure and provenance (ADR 004). A builder-vm
materializes but cannot approve, sign or publish it. No production
release is authorized by passing local or PR-only synthetic tests.

## Per-architecture versions

**Decided by the owner on 2026-11-11 (recommendation accepted).** One descriptor targets one
`guest_arch`, a published version is immutable so two descriptors cannot share a version,
and the `mvm` client filters versions by host architecture and then takes the highest
semver (`resolve_matching` in `discovery.rs` in the `mvm` repo; the strict architecture
resolver is `mvm#5298`). The scheme: within one release line the x86_64 build takes `X.Y.0`
and the aarch64 build takes `X.Y.1`; a new release line bumps the minor. This is the
numbering the unpublished two-architecture Python layer fixtures already use (x86_64 `1.1.0`,
aarch64 `1.1.1`, draft PR #154), so every pack follows one convention. Which architecture is
built first does not change the numbers. The scheme starts at a NEW release line, not at the
published `agent/claude` 2.0.x (2.0.1 is already an aarch64 build). Only the version numbers
in the pack sources and these docs depend on it.

See also the [application pack guide](../application-packs.md).

## Status and acceptance

`mvm` PR #5228 stages v2 authoring, signed runtime descriptors, strict
filesystem composition and signed-base-tar acquisition. Draft PR #5263
adds a fixed-default-base development CLI path and host-signed local
inventory. The fixed-base assumption must be refactored into the
selected-base input of the **same** composer, cache and admission path.
Neither PR proves the selectable-base contract or protected export.
The latest known signed image set, `v0.2.4`, has no generic composition
tar; do not advance `images.lock` without the release prerequisites
and authorization. A PR-only synthetic signer/base is suitable for
testing but does not enroll a production trust anchor.

Acceptance requires both default and custom-base **`mvmctl` CLI**
launches on Linux, guest-output values from cold and repeat runs,
verified cache reuse, and refusal tests for tampering, revocation,
incompatibility, policy widening and path conflict. Direct-QEMU
guest reads alone are not CLI/admission/cache evidence. Report exact
Linux CI, formatting, Clippy, footprint and registry checks, plus
cold assembly time, repeat boot time, transfer and disk retention.
The author fast path targets declarative source -> pinned lock ->
builder-vm candidate -> protected verification/signing/publication;
`mvmctl pack publish ./my-pack` remains future work until that
boundary can be enforced. Do not redistribute Claude in synthetic
acceptance without separate rights and release approval.
