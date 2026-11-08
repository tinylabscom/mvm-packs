# Prior art: how an OCI-based microVM tool distributes packaged machines

Status: research note, not a decision. Date: 2026-11-06.

## Scope and method

This compares `mvm-packs` with another microVM tool whose packaged machines are pushed
to and pulled from a registry, because its user experience is the one we want. Read:
its pack crate (file format, packer, extractor), its registry client crate (push,
pull, cache, authentication), the pack CLI subcommands, and its pack and security
documents, on the `main` branch on 2026-11-06. Nothing was run.

Not read, because it is not in that repository: its hosted registry service, the
registry web pages, and its authentication service. Anything below about how the
official namespace or the web catalog is populated is therefore inferred, and says so.

## 1. How it models a pack

- **One portable file.** A compressed tar of assets, a JSON manifest, and a fixed
  64-byte footer holding a magic string, a format version, offsets and sizes, and a
  CRC32. It ships either as a sidecar next to a launcher or embedded in one
  executable.
- **Format versioning.** It names the current version and also a set of older
  versions it can still read. The set exists because a refactor once reset the
  version number and stranded older files behind a strict equality check. New
  manifest fields default, so old files still load.
- **Manifest content.** Source image reference and digest, the guest platform, the
  host platform the artifact runs on (a separate field), entrypoint, command and
  environment, secret references by name and never inline, CPUs and memory,
  extracted size, default network setting, a creation timestamp, the builder's
  version, and an inventory of assets with a path and size each. Assets carry no
  per-asset hash.

## 2. How it distributes: standard OCI Distribution

- A pack is an ordinary OCI image manifest: the **config blob is the pack manifest**
  (its own media type) and a **single layer blob is the whole pack file**. The
  OCI 1.1 `artifactType` is stamped so artifact-aware tools classify it. Any
  compliant registry can host it.
- **One tag, many platforms**, through an OCI image index keyed by the host
  platform. A pull picks the caller's platform automatically.
- **Namespaces.** An official `library/` namespace and per-tenant namespaces on its
  hosted registry. Reference grammar is `registry/repo:tag` or `@sha256:digest`.
- **No hijacking.** A bare Docker-style name is deliberately not reinterpreted as a
  pack reference, and the pack media type (by vendor prefix) is the only trigger.
  Classifying a reference as "not a pack" is fail-open by design, so it can never
  break ordinary image pulls.

## 3. Discovery without downloading

`pack inspect <ref>` fetches only the manifest and the small config blob, and prints
the reference, source image, guest platform, host platform with an "incompatible"
flag against the current host, CPUs, memory, entrypoint, creation time, builder
version, size and digest. This is the property our pages lack for application packs:
ADR 001 says archive-only fields such as the environment, entrypoint and created
date need a verified pull, because they live inside a 450 MiB archive.

## 4. Transport engineering worth knowing about

Digest strings are validated (`sha256:` plus 64 hex) so a path-traversing digest is
rejected at the boundary. Manifest and index responses are buffered only up to a
cap, checked while streaming so a lying `Content-Length` cannot get past it, and
before any digest is computed. Downloads go to a `.partial` file, resume across
attempts, retry with doubling backoff only for transient faults (transport and 5xx;
a missing blob, an auth failure or a digest mismatch are terminal), and are verified
from the finished file. Large blobs can be fetched as parallel ranged parts, with a
per-blob lock so two pulls of one blob do not collide, and stall detection that
reports bytes received against bytes expected. Uploads fall back to the OCI chunked
mode when a single request is rejected. A content-addressed local cache evicts by
last use under a size cap. Bearer tokens are cached across processes, scoped to the
registry, challenge, scope and a fingerprint of the credentials, and only pull-scoped
tokens are persisted.

## 5. Its trust model, stated plainly

This is where we differ most, and where the comparison does not flatter it:

- A pack's identity is its digest. The file carries a CRC32. There is **no
  publisher signature on packs**. Its own README says a checksum detects
  corruption and is not proof of publisher identity; its security policy lists
  unsigned release archives as a documented limitation.
- The only "signing" in the pack crate is macOS ad-hoc code signing, so the
  hypervisor entitlements apply to a launcher. It is not publisher authenticity.
- Access control is registry credentials (bearer, basic, or an identity token
  exchanged with a token service).
- It documents, honestly, that its brokered peer-to-peer blob fetch is not
  tenant-scoped and is safe only on single-tenant or public-artifact fleets.

## 6. Authoring and operations documents

A pack guide with a procedure and a list of traps. Two ideas stand out. **"Assert a
value, not a boot"**: a pack that lost its root filesystem still boots and exits
zero, so verification writes a marker into the source and reads it back out of the
artifact. And a **version-skew note**: packs built by older versions lose file
ownership, `inspect` shows the builder version, and the runtime warns on each
extraction of an affected pack.

## 7. Side by side

| Concern | The other tool | `mvm-packs` today |
| --- | --- | --- |
| Where artifacts live | Any OCI registry | Git (`index.json`, manifests); archives as GitHub release assets |
| Metadata without a full download | Yes, the config blob | Index and manifest only; environment details are inside the archive |
| Multi-architecture | One tag, OCI index by host platform | One architecture per descriptor; other architectures are other versions |
| Integrity | Digest, CRC32 in file | Archive digest and size, per-artifact SHA-256, Ed25519 manifest signature |
| Publisher authenticity | None on packs | Keyless signature on the descriptor; key bound by `key_id` |
| Revocation | Not found | Signed, short-lived feed |
| Pre-publication checks | Not found | Registry gate: structure, hashes, signature, requirements, binary pin, environment policy |
| Secrets | References by name | Slots by name |
| Format and compatibility | Version plus supported-read set; builder version recorded | Schema versions; embedded runtime asset version recorded, builder version not seen |
| Download robustness | Resume, ranges, locks, caps, cache | Publisher downloads the whole archive serially (about 3.5 minutes) |
| Namespaces | Official plus tenants | Official roots reserved; separate community root (ADR 002) |
| Author documentation | Procedure plus traps | Guides for policy packs; application packs not yet |

## 8. What we can learn

Effort is the rough size of the change, not a commitment. "Client" and "builder" work
belongs to the `mvm` repository.

**Adopt in the registry (this repository)**

1. **Show recorded archive details on pack pages.** The publisher gate already opens
   the archive. Let it also write a small record (architecture, creation time,
   kernel and rootfs hashes, the signed environment policy, entrypoint, resources,
   secret slots, the binary pin) beside the generated pages, labelled as recorded
   by the publisher at signing time and re-verifiable by a pull. This gives pages
   the "inspect without downloading" experience without changing the signed
   descriptor or the client. Small to medium.
2. **Cache the archive by digest in CI.** The gate's serial download dominates a
   publish run. A digest-keyed cache removes it on reruns. Small.
3. **Write the application-pack author guide** with a traps list, modelled on theirs
   (ADR 003 requirements, the environment policy, the key file beside the archive).
   Small.

**Adopt as acceptance practice**

4. **Assert a value, not a boot.** The #76 boot test should read a known value out of
   the running artifact (for example the exact `claude --version` output and one
   search result), not only observe a clean exit.

**Propose to the client and builder owners**

5. **Record the builder version in the signed bundle manifest** and have `inspect`
   warn on skew, as their version-skew note does. Small, builder.
6. **Per-platform fan-out for one version**, an index of descriptors keyed by
   architecture, so an unpinned pull picks the host's architecture. Needs a schema
   version and a client change; the per-version architecture field `mvm` already
   plans is a step toward it. Medium.
7. **A transport checklist for the client**: digest-format validation, response size
   caps checked while streaming, resumable partial downloads verified from the
   finished file, a per-blob lock, bounded retries that separate transient from
   terminal faults, a content-addressed cache with eviction. Large, client.
8. **Digest-pinned OCI hosting for archives.** Our descriptor validator already
   accepts `oci://host/repo@sha256:` sources. Hosting archives in an OCI registry
   would add resumable ranged downloads, mirrors, and the option to sign the
   archive itself as an OCI artifact, which would close the gap that no archive
   provenance exists today. Needs client support for the `oci://` source and a
   decision on where the archive is hosted. Medium to large.

**Do not copy**

9. Digest-as-identity with no publisher signature; unsigned release archives; the
   fail-open classifier (ours must fail closed); unscoped peer fetch; assets
   without per-asset hashes; launcher binaries that execute on the host.

## 9. Confirmations this gives our own decisions

A separate official namespace and community root (ADR 002) avoid the namespace
hijacking their routing code has to guard against. Keeping archive bytes out of git
and pinning them by digest matches their model of a registry blob. Our extra layers,
the signed descriptor, revocation, key binding and the pre-sign gate, are exactly
what their own documents say is missing from theirs.

## Not verified

How their official namespace and web catalog are populated and curated; how their
hosted registry authorizes publishers; whether the web pages read the config blob or
a separate catalog. If one of these matters for a decision, it needs a source other
than their public repository.
