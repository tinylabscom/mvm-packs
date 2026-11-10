# ADR 004: Portable application components and self-contained exports

Status: proposed contract; not a released format
Date: 2026-11-06; revised 2026-11-10
Related: [ADR 001](001-pack-contents.md), [ADR 005](005-runtime-layers.md),
[ADR 006](006-runnable-composable-packs.md); `mvm`
`specs/contracts/composable-pack-build.md`

## Decision and compatibility

Do **not** turn a policy-only pack into an empty `.mvmpkg`, or call a
kernel-and-rootfs bundle a portable application component. A new versioned
application format contains the signed application bytes, immutable identity,
architecture and ABI/libc requirements, declared file inventory, policy and
entrypoint candidates; it contains **no kernel, bootable rootfs or guest
runtime**. Runtime/tool components use their own signed descriptor and
digest-bound payload (ADR 005). Neither an app nor a runtime component is
independently bootable. A new schema/kind is required: readers must reject
unknown versions instead of interpreting them as the existing schema-2
application descriptor or schema-7 boot bundle. The exact new wire schema,
size caps and canonicalization must be shared with the `mvm` verifier before
the registry can publish any such version.

All nine historical policy-only versions retain their exact bytes, signatures,
revocations and non-runnable meaning. `agent/claude@2.0.0` and `@2.0.1`
remain complete, signed boot bundles behind schema-2 descriptors; they are
not relabelled as portable application components. Keep the v1 release reader
and existing v1 authoring usable while v2 reaches parity. A new version,
not an edit to a published manifest, introduces the portable application.

## Trust and ownership

The registry's keyless signature authenticates a component descriptor,
including its external archive's digest, size, identity, requirements and
declared policy; a verified descriptor does not enroll a key, grant a
capability or authorize a workload. The component archive is snapshotted and
checked against the signed digest before any extraction. A runtime layer has
**one** keyless-signed descriptor binding its archive; it does not acquire a
second Ed25519 archive signer. Legacy `.mvmpkg` bundles retain their existing
independently trusted Ed25519 signature. Do not silently substitute either
trust root for the other.

The selected bootable Linux base and the guest runtime are separate inputs
supplied by `mvm`, not contents of an application pack. The boot closure
includes the kernel, initramfs, base filesystem composition input, guest
runtime and their measured/signed evidence. An operator may select a
compatible independently built base (builder-vm, SDK or Nix); a locally
built base is **development only**, even if the local host signs a receipt.
Production requires separately enrolled, independently verified, signed
base evidence. An incompatible or unsigned production base fails closed;
there is no implicit fallback to the default.

`mvm` owns format verification, resolution, assembly, cache, launch and
admission. `mvm-images` can publish a signed default base, but does not own
the generic selectable-base interface. This registry owns component
descriptors, publisher checks and revocations. A builder-vm can materialize
candidate bytes but must never hold protected release signing or publication
authority.

## The one-file boundary

Local composition creates a **measured ext4/verity workload before first
boot**. Its host-signed local bundle and signed plan bind the ordered
authenticated inputs, selected base and guest runtime, output hashes,
effective policy and actual admitted command. This is a development receipt,
not the application publisher's signature. Every run, including a cache
hit, must independently recheck component/base publisher trust, fresh
rollback-protected revocations, policy and host grants.

Production export is a different operation: the protected pipeline
independently verifies the frozen inputs, selected boot closure, output
measurement, policy, actual command and boot witness, then signs a
**self-contained `.mvmpkg`**. Its signed provenance binds the ordered
component manifest digests and policy-document hashes, the selected base
evidence, guest-runtime evidence, assembler version, ext4/verity output
hashes and health-tested command. An offline verifier must authenticate the
publisher and all required input/base evidence and apply current
revocation/admission rules; no cache, builder receipt or host signature may
be promoted by relabelling. Signing/publication needs separate explicit
release approval. A synthetic test signer may test this boundary but never
claim the official publisher identity.

The eventual transport/OCI encoding and in-file keyless provenance format
are still open format work. Neither a new in-file signature nor a
`mvmctl pack publish ./my-pack` command is implied by this ADR. Do not
publish a descriptor until a compatible consumer and protected verification
gate are present.
