# PS-06 portable-runtime proposal: source review

## Exact packet

- Base: `911eb7143d89ec2bb2c30666f18c4eade0ac0697`
- Proposed tree: `56f34e6f3dcffcf93b777ae2a64cd79db8a95929`
- Patch SHA-256:
  `a784ebff43b801a97ae2f9d8140691e59cf9a3a088642c76b0757ba0ca4de4b7`
- Patch: 98,212 bytes; exactly 14 modified files, not the donor branch wholesale.
- Manifest SHA-256:
  `b83674f86d5b6b4a762d0a00d4963a41b14a7dd59dd87da16ba227d314efd718`

Independently read and matched every base/proposed blob hash in the manifest and
the exact tree changeset. Reviewed the critical exporter, contract, core
selection, consumer attachment and legacy-refusal changes, plus structural and
refusal fixtures and constructor references.

No source was applied, compiled, signed or executed. No runtime/resource grant
is created by this review. This is not a completed cold-consumer acceptance.

## Preserved boundaries

- Explicit schema-6 floor and closed CLI boot-assets declaration.
- Mixed legacy/full-image-set and CLI runtime declarations refuse.
- Consumer configuration is committed only after successful verification.
- The existing #4409 release-runtime verifier remains the authentication path.
- Unsigned/tampered synthetic runtime fixtures are refusal tests, not evidence
  of a genuine compatible release.

## Acceptance-blocking kernel-proof gap

In the reviewed path, the CLI boot-assets declaration retains image-set JSON,
and selection checks structure, completeness, kernel role, digest and size.
[The existing core embedded-image-set verifier](https://github.com/tinylabscom/mvm/blob/911eb7143d89ec2bb2c30666f18c4eade0ac0697/crates/mvm-core/src/plan/bundle.rs#L1105-L1186)
authenticates those bytes through the application bundle publisher; it does not
independently verify the original Linux manifest signature, accepted compiled
root/lock or current revocations.
Raw exporter inputs plus a caller-supplied manifest hash are not that proof.

This is a missing required demo proof, not a claim of a runtime-reproduced
exploit or an assertion about every legacy bundle's trust contract.

Before demo acceptance, either identify the existing canonical kernel gate and
show it executes on these same retained bytes before backend effects, or reuse
the reviewed canonical kernel-proof mechanism. Do not make an application key
implicitly authoritative for CLI/runtime/kernel roles or invent another signer.

Required negative case: coherently replace the kernel and embedded image-set
JSON, re-sign the application bundle, and still refuse against the independent
canonical kernel authority.

## Positive-input dependency

The runtime owner's current release inventory found no compatible published
runtime quartet: v0.22.0 and the host-helper source-build release do not supply
the required guest-runtime assets. The proposed Release path cannot reinterpret
the existing private Source runtime as a Release.

Before a positive cold-run claim, identify one concrete input/authority route:
genuine compatible Release inputs through the normal authorized release process,
or an actually implemented and reviewed private Source operator-purpose/kernel
custody route within its explicit authorization. Synthetic proofs, author flags
and a generic application signing key do not supply that authority.

The proposal also explicitly excludes same-health-closure producer wiring,
actual named application pull and a signed composable-policy carrier. Those
remain separate implementation/validation requirements.

## Disposition

**Not accepted as a demo cold-boot unblock.** Kernel-proof resolution and an
actual positive-input route are required. No full source, compile, runtime or
publication approval is inferred. The runtime owner is the sole implementation
writer and supplies an updated immutable packet for the next review.
