# Composable application packs: design for the demo

Status: draft for owner approval. Nothing here is built, signed or published.
Author: the `mvm-packs` session, from the owner's decisions of 2026-11-11.
Builds on: draft PR #147 (`feat/portable-composition-contract`, portable component
format candidates) and ADRs 004 to 006. Where this document and an ADR disagree,
this document records the owner's decision and the ADR must be updated.

## Intent and why

A user should be able to combine registry packs into one workload with a single
command, keep every pack's safety and security boundaries, and bring their own
base. The registry supplies applications, policies, guarantees and requirements.
It does not supply the machine they run on.

Why it matters now: the owner wants this working for a demo. Packs that bundle a
backend base (a kernel and root filesystem) force one environment on every user and
make a user's own Nix templates or OCI images second-class.

## The demo scenario

One command launches a VM that has:
- the `runtime/python` layer, so Python programs run;
- the `agent/claude` application, with its policy and its requirement for an
  `ANTHROPIC_API_KEY`;
- the user's own Python program as the entrypoint, talking to the Claude app;
- the user's own base (their Nix template or OCI image), not one the registry chose.

The combined policy is the Claude policy together with the user's policy.

## Goals

- A pack carries the application, its policy and its requirements, and nothing else.
- Policies compose so a pack's limits can only be narrowed by another pack, never
  loosened. A deny anywhere wins; ceilings narrow; a pack's requests are
  intersected with host and user grants.
- Requirements are explicit and checked before launch: secrets (for example
  `ANTHROPIC_API_KEY`), libc and loader, minimum kernel, capabilities. A
  combination that cannot satisfy them is refused with a specific reason.
- One user-facing command does the whole job: no separate prepare, assemble or
  install step.
- Everything the registry publishes stays signed, immutable and revocable.

## Non-goals

- The registry does not build or ship a base image, kernel or root filesystem.
- This work does not publish a "runnable default" for any pack.
- No change to how existing published versions are verified.

## Anti-goals (a failure even if it technically works)

- A pack that only boots on a registry-chosen base.
- A combination that silently runs with a weaker policy than any one pack allows.
- A secret or host grant given without explicit approval.
- Anything signed or published because another session asked for it.

## Decisions made by the owner

1. `agent/claude` is an application pack: the application, its policy and its
   requirements. It does not carry a kernel, root filesystem or backend.
2. The base layer is chosen by the user driving the application, from their own
   Nix templates or OCI images. The registry must not override that.
3. Policies compose as described in Goals; the user's policy and the Claude policy
   both apply.
4. Entrypoint: a custom entrypoint wins. If there is none, the last pack defined
   supplies the entrypoint. This replaces the ADR 006 text that said the named
   runnable pack owns the default.
5. The user needs a single CLI command for the whole flow.

## Constraints

- Published `agent/claude@2.0.0` and `@2.0.1` are immutable, signed and approved
  by the owner as exact archives. They are not changed or revoked. An
  application-only `agent/claude` is a new version with a new signed archive.
- Signing and publishing go only through the registry publish workflow, with the
  owner approving the exact archive. No peer message authorizes either.
- The `runtime_layer` publication gate stays closed until a compatible `mvm`
  consumer, an admission check and a real boot witness exist (see PR #147).
- Redistribution rights for the embedded Claude executable are a release
  prerequisite that a signature does not prove.
- `mvm` owns the component assembler, the client cache, verity creation,
  signature verification, policy admission and the run command. This repository
  owns signed descriptors, catalog and publisher checks, revocation publishing
  and displayed provenance. Neither side delivers the demo alone.

## Current state (facts as of 2026-11-11)

- `main`: ADR 006 proposes runnable defaults; the registry gate in `build-packs.py`
  requires an archive with a kernel and a root filesystem; `runtime/python` exists
  only as an unpublished fixture and the tooling refuses to sign layers.
- PR #147 (draft, open): unpublished schema-3 `application_component` and
  schema-4 `runtime_component` / `tool_component` descriptors and validators. An
  application component binds one payload archive by digest and size, requirements
  (filesystem ABI, libc, loader, minimum kernel, capabilities) and named
  entrypoints, with no kernel, rootfs, launch grant or install script. Its text
  already orders entrypoints as: explicit command, then the last application
  with a `default` command. `build-packs.py` refuses all new kinds until the
  consumer, admission and signing gate exist. Missing: verified libc and kernel
  evidence for a selected base, generic ordered-graph launch, a CLI cold and
  repeat-run witness, and a production export.
- `mvm` (other sessions): the Python layer builder and its checks are merged
  (#5228, #5273). Drafts #5326 and #5323 add the ordered graph and entrypoint
  request, schema-3 application and schema-4 runtime/tool readers, and a signed
  production-composition candidate. Nothing is released; the official Python
  signing key slot is empty. Launch still takes its workload kernel from the
  published image set (`prepare_workload_kernel_for_launch`, #5321) unless the
  user's base supplies one, and base resolution plugs in at
  `resolve_launch_image_source`.
- The guest mailbox and plan fields are independent of the base and the
  entrypoint, so this design needs no change to `plan.mailbox`.

## Design

**What a pack is.** A signed descriptor plus an external payload archive pinned by
digest and size. The payload holds only the application files (for example a static
binary under `/srv/app`). The descriptor holds the policy documents
(`pack/group.toml`, `pack/profile.toml`), the requirements, and named entrypoints.
Secret needs live in the profile, for example the Anthropic secret binding.

**Kinds.** `application_component` (for example `agent/claude`) and
`runtime_component` (for example `runtime/python`) as in PR #147. A runtime
component usually has no `default` entrypoint, so the entrypoint rule skips it.

**Composition.** The client takes an ordered list of packs and the user's base.
It verifies each signed descriptor and payload digest, checks every requirement
against the chosen base, composes policy by the rules above, and refuses on any
mismatch or on a revoked or unverifiable input. Trust, revocation and grants are
rechecked on every launch, including from a cache. The composed policy digest is
recorded in the launch record.

**Policy composition rules (already specified, extend rather than redefine).**
`scripts/policy_compose.py` is the registry's reference composer and the
conformance oracle for the `mvm` client merge (`policy_profiles/merge.rs`); the
vectors are `tests/policy-vectors/vectors.json`. The rules today: allows union,
denies union, a deny beats an allow, tools rank deny over ask over allow, resource
limits take the smallest bound, and a share is writable only if every layer says
so; two layers that mount different hosts at one guest path are a hard error.
The user's policy is one more layer in the `--policy` order. Not yet covered by
vectors: network canonicalisation and block, secret-host narrowing, `env.readmit`,
pack-added shares. Each new rule lands with a vector on both sides. An empty
result is a refusal, not a silent narrowing (builder's call, see below).

**Boundary for composition.** This repository ships only the reference composer
and shared vectors, plus static validation of descriptors. It never composes at
run time. The `mvm` client is the one authoritative implementation and the only
place the requirements are checked against the chosen base (it has the libc,
loader and kernel evidence; the registry does not).

**Entrypoint.** Explicit command after `--`, then the user's custom entrypoint,
then the last pack in order that declares a `default` entrypoint.

**One command (a guess, for the `mvm` side to settle).** Something of the form
`mvmctl run <packs in order> --base <nix flake or OCI ref> -- <command>`. The
exact syntax belongs to the `mvm` owner. The requirement is that it is one command.

**Registry deliverables for the demo (a guess at the minimum).**
1. Land and finish the PR #147 candidates for the demo path.
2. A new application-only `agent/claude` version: payload archive, profile with
   the `ANTHROPIC_API_KEY` secret requirement, requirements for the chosen
   architecture.
3. A `runtime/python` runtime component built from the existing `mvm` Python layer
   builder output, one architecture first.
4. Policy composition vectors covering the demo: Claude policy plus a user
   policy, deny wins, ceilings narrow, request intersection.
5. Catalog and pages show kind, requirements and policy for the new kinds.
6. ADR 004 to 006 updated to match the decisions above.
7. A reviewed, owner-approved publish of the exact archives through the protected
   workflow, only after the `mvm` consumer, admission and a boot witness exist.

## Coordination

- This session owns the registry side above. It edits `docs/adr`,
  `scripts/build-packs.py` and its gates only on the owner's approval of this
  design.
- `mvm` sessions own the client side. mvm-7d confirmed guest mailbox and
  admission do not assume a pack supplies a base or an entrypoint. The owners of
  #5326, #5323 and the Delta thread on `feat/portable-composition-contract` are
  not yet identified by name; the owner is asked to name them.
- The wire fields of the descriptors are a proposal until the `mvm` format owner
  agrees them (stated in PR #147).

## Calls made by the author (check these)

- The registry ships the reference composer and vectors, not a run-time composer.
- Build on PR #147 as it stands. Treat its wire fields as frozen unless the `mvm`
  format owner asks for a change, so the first registry PR is stacked on #147 and
  is not blocked on naming that owner.
- Payloads are HTTPS release assets pinned by SHA-256, the existing mechanism, and
  `build-packs.py` reads them back before any signature. The Claude binary uses
  the same upstream and pin policy as `agent/claude@2.0.1`. The Python payload is
  the output of the `mvm` layer builder, attached as a pinned release asset.
- `index.json` stays at its current schema for the demo. New kinds are not listed
  until they are published, and older clients keep parsing the catalog. How they
  are listed after publication is settled with the `mvm` owner.
- Nothing is written to `packs/` before the publication gate lifts. Everything up
  to the signing step may be built and tested unsigned.
- Updating ADRs 004 to 006 and the gate in `build-packs.py` starts only once the
  owner approves this document.
- An empty policy result is refused with a specific reason, never narrowed silently.

## Left to the builder

File layout, test structure, exact validator wording, catalog and pages rendering,
and how to stage the work across PRs.

## Alignment with the `mvm` composition thread (read 2026-11-11, read-only)

Source: the Delta thread "Implement composable application pack release candidate"
(worktree `mvm/.delta/worktrees/x5xcrgbp79bd`, branch `feat/portable-composition-rc-main`,
PR #5326) and its `specs/contracts/composable-pack-build.md`.

- Wire format: its `application_component` reader (schema 3, component schema 1) and
  its runtime/tool reader (schema 4, component schema 1) match PR #147 on every point
  checked: kinds, filesystem ABI 1, libc `static`/`musl`/`glibc` with loader rules,
  minimum kernel, at most 16 capabilities, at most 16 entrypoints or dependencies,
  2 GiB payload cap, exact manifest pins, no second archive signer.
- Entrypoint: its contract says runtime override, then user-defined workload entrypoint,
  then the last application in explicit order declaring an entrypoint. "Last wins"
  applies only to command selection, and the chosen command is separately admitted.
  This is the owner's rule.
- One command: its contract says an explicitly ordered composition with `--base` is a
  single command, and `mvmctl run agent/claude` stays one command. A development-only
  `mvmctl run --compose PACK.TOML` exists and does not yet consume signed descriptors.
- Policy: signed component policy cannot grant itself network, secrets or shares;
  denies win and ceilings narrow, matching `scripts/policy_compose.py`.
- Tension to settle: the contract keeps "a fast compatible default" for
  `mvmctl run agent/claude` when no base is chosen. The owner's decision is that a pack
  never carries or forces a base. A client-side fallback is compatible only if it comes
  from `mvm`, never from the pack, and only when the user gave no base.

## Answers from the owner (2026-11-11)

- Architectures: aarch64 first, but x86_64 is paramount: both ship for the demo, and
  nothing may be designed so that x86_64 is an afterthought. Each descriptor targets
  one `guest_arch`, so every pack is built, pinned and tested once per architecture.
  The demo date is not stated yet.
- Redistribution: the Claude executable may be redistributed in a registry payload.
  The owner assumes the licensing risk and authorizes it. This covers redistribution
  only. Signing and publishing still need the owner's approval of the exact archive
  through the protected workflow.

## Open items for the owner

- Which session or person is the `mvm` format owner for the wire fields (being
  discovered by messaging the other sessions; `specs/contracts/composable-pack-build.md`
  in `mvm` says only that the format owner is `mvm`, coordinated with the registry).
- The demo date.
