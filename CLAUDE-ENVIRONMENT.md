# Claude Code environment delivery plan

Status: planned, not published. This document describes the first runnable
environment pack; it is not an installation guide or evidence of a release.

- Delivery epic: [mvm#4222](https://github.com/tinylabscom/mvm/issues/4222).
- Claude environment: [#31](https://github.com/tinylabscom/mvm-packs/issues/31).
- Official image publication: [#12](https://github.com/tinylabscom/mvm-packs/issues/12).

The existing `agent/claude` pack is a signed policy pack, not an installed
Claude Code environment. Preserve its contract and published bytes. The image
publication guard described in [README.packs.md](README.packs.md) remains in
force until producer and consumer verification are implemented together.

## Product and ownership

Deliver one signed, self-contained `.mvmpkg` per supported guest architecture.
A compatible host with `mvmctl` can verify, install and boot it without the
author's source, Nix, original download registry or a populated image cache.
Claude's actual model use still needs authorized network access and credentials.
Scenarios and graders are optional follow-up features, never prerequisites for
an ordinary environment.

| Component | Responsibility |
| --- | --- |
| Author SDK | Construct a versioned neutral specification |
| Shared Rust compiler | Resolve/lock inputs and extend existing `mvm-sdk` lowering |
| `mvm-images` | Publish the pinned generic Linux base and builder image |
| Builder/materializer | Produce artifacts, logs and provenance; no signing or publishing |
| `mvm-client` / `mvm-bundler` | Validate and export using the caller-authorized signer |
| Protected release job | Verify evidence, authorize signing and publish immutable releases |
| Existing verifier/admission | Verify publisher, artifacts, compatibility and requested capabilities |
| This repository | Own the Claude recipe, catalog metadata and release witnesses |

Do not create a second Nix renderer, OCI downloader, filesystem builder,
bundler, signer or registry verifier in a language SDK. Do not trigger an
`mvm-images` release for each application build.

## Authoring contract

Use generic packages, independently from application-language dependencies:

```python
# Proposed API shape only: the SDK and this recipe are not delivered yet.
pack = (
    Pack("acme/example", version="0.1.0")
    .package("python", version="3.12")
    .dependencies("python", requirements="./requirements.txt")
    .copy("./app", "/opt/app")
    .entrypoint(["python", "/opt/app/main.py"])
    .resources(cpus=2, memory_mib=2048)
)
```

Python, TypeScript, Rust and Kotlin/JVM definitions must resolve to the same
neutral specification. Python authoring must not install Python in the guest.
Construction produces data; `build()` explicitly invokes the shared compiler.
Evaluating the author program itself is arbitrary code execution and must be
isolated from release credentials.

The Claude recipe will use a generic package with an explicitly resolved source,
not a hardcoded `.claude()` SDK method. Do not invent a package name/version
mapping before the shared resolver supports it.

## Claude source and release prerequisites

Candidate source: the unmodified official native Linux binary, pinned to an
exact upstream version and per-architecture SHA-256. This is a recommendation,
not a selected version or an approved redistribution.

- Review [Anthropic's preinstallation and compliance requirements](https://code.claude.com/docs/en/legal-and-compliance)
  before distributing bytes. Record approval and the terms reviewed in #31.
  Explicitly resolve compatibility with authentication-method requirements;
  API-key-only operation is not, by itself, distribution approval.
- Select architecture/libc variants compatible with the pinned base. Preserve
  upstream checksums and the source manifest in build provenance.
- Do not run `curl | bash`, resolve `latest`, or install dependencies at guest
  startup. Review supported immutable-image/update configuration rather than
  patching the upstream binary.
- Recheck [upstream system requirements](https://code.claude.com/docs/en/setup)
  when selecting the release. The investigated memory floor is 4 GB: declare
  at least 4096 MiB, and witness that launch applies the recommendation subject
  to host policy. Bundle resource metadata alone is advisory.
- Declare writable workspace/configuration needs explicitly. No automatic host
  home-directory mount, credentials mount, or writable rootfs.

## Terminal, network and authentication

An application terminal and an administrative VM console are different grants.
Existing development PTY support is not proof that a sealed Claude environment
can be interactive. [mvm#4227](https://github.com/tinylabscom/mvm/issues/4227)
must preserve the sealed-console refusal while providing separately authorized
access to the declared unprivileged application, with resize, signals, exit
status, disconnect and detach/reattach witnesses.

Never use a development profile or `accessible=true` as a production workaround.
Claude can itself execute commands; terminal access does not replace its
filesystem, tool and egress policies.

The initial authentication candidate is a host-held Anthropic API key substituted
by the existing host endpoint for approved requests to `api.anthropic.com`.
The guest receives only the existing opaque placeholder, never the raw key.
Verify Claude's proxy behavior, first-run interaction and actual header
substitution; a configured environment variable is not evidence of success.

Subscription/browser login is unproven and must not be advertised as supported.
Its investigation and upstream terms review remain release gates. Do not mount
host Claude credentials or persist raw login tokens in the guest as a shortcut.

All external networking stays on authenticated vsock/FlowMux. No guest NIC,
TAP/TUN or alternate network stack. Requested permissions are not grants:
admission and host policy remain authoritative.

## Build, sign and publish

1. Evaluate author code in a credential-free isolated job; emit bounded data
   and a source snapshot.
2. Resolve and freeze the specification, dependency hashes, compiler version,
   builder digest and accepted base-image-set pin.
3. Build without publisher keys or registry write credentials.
4. Validate artifact structure, sizes, architecture, sidecar, verity and complete
   boot closure before running anything.
5. Freeze artifact digests and test in a disposable workload VM. Refuse any
   change between tested and signed bytes.
6. For official publication, independently rebuild and compare payload bytes.
   Bind provenance, SBOM and test evidence to those same digests.
7. A fresh, protected release job runs pinned trusted tooling, verifies the
   artifacts/evidence and invokes the existing signer. It never executes pack
   setup scripts. Prefer OIDC-authorized external Ed25519 signing compatible
   with `BundleSigner`; OIDC does not replace the `.mvmpkg` signature format.
8. Verify/install and smoke-test the final signed archive before publication.
   Publish immutable artifacts and digest-bound registry metadata.

The current keyless Sigstore signatures for lightweight registry packs and the
publisher-key signature of `.mvmpkg` are distinct contracts. A publisher display
name is not a trust anchor. Define their verified identity binding rather than
treating either signature as a substitute for the other.

Do not remove the source-image publication guard just to unblock Claude.
Implement the image release kind and client verification together under #12.
Retain base-lock acceptance, rollback-resistant revocation and explicit offline
trust freshness rules. Signed means attributable and intact, not safe.

## Delivery sequence and evidence

GitHub issue checkboxes are the live progress record. This table describes exit
criteria, not completed work.

| Order | Work | Required witness |
| --- | --- | --- |
| 1 | [Neutral contract #4223](https://github.com/tinylabscom/mvm/issues/4223) | Strict versioned DTOs, schema and language-neutral fixtures |
| 2a | [Locked compiler #4224](https://github.com/tinylabscom/mvm/issues/4224) | Deterministic context/dependencies through the existing compiler |
| 2b | [Portable requirements #4225](https://github.com/tinylabscom/mvm/issues/4225) | Typed signed requirements survive export/install/admission |
| 3 | [Python/TypeScript slice #4226](https://github.com/tinylabscom/mvm/issues/4226) | Equivalent definitions; build, health, sign, install and source-free run |
| 4 | [Terminal/auth #4227](https://github.com/tinylabscom/mvm/issues/4227) | Authorized application PTY and host-mediated auth without weakening sealed admission |
| 5 | [Claude recipe #31](https://github.com/tinylabscom/mvm-packs/issues/31) | Pinned native binary, loader check and archive-only boot |
| 6 | [Public release #12](https://github.com/tinylabscom/mvm-packs/issues/12) | Reproduction, signatures, provenance, trust/revocation and real usability |

Source/terms and terminal feasibility investigation may run in parallel with
contract work. Dependent implementation plans wait for the actual contracts.
[OCI input #4220](https://github.com/tinylabscom/mvm/issues/4220) is a later
adapter, not a dependency for the first declarative recipe.
[Rust/Kotlin #4228](https://github.com/tinylabscom/mvm/issues/4228) and
[scenarios #4229](https://github.com/tinylabscom/mvm/issues/4229) follow the core
vertical slice.

Keep three results distinct:

1. `claude --version`: binary selection and loader compatibility only.
2. A deliberately bounded, authenticated request with explicit user consent:
   proxy/auth/model usability. No paid calls or login in ordinary CI.
3. Official publication: all release, terms, reproduction and trust gates met.

## PR and worktree lifecycle

Each implementation issue has its own focused branch and PR. Record exact tests
and missing witnesses; do not check an acceptance box on mocks alone when it
requires a real boot. Documentation PRs reference #31 but do not close it.

Keep task worktrees while a PR is under review. After merge or deliberate closure,
record the disposition, preserve unfinished/uncommitted work, then remove only
the clean task-owned worktree. Never force-remove a dirty checkout. Delta-managed
worktrees must use Delta's lifecycle rather than manual deletion; if cleanup
cannot be performed, leave its issue checkbox open and report the blocker.
