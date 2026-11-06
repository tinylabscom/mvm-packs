# ADR 002: Third-party pack publishing

Status: proposed (community index section revised)
Date: 2026-11-05
Related: [ADR 001](001-pack-contents.md), `mvm` ADR-055 (pack naming and trust)

## Purpose

Anyone should be able to publish a pack from their own GitHub repository, with
the same experience a consumer gets for first-party packs: one page per pack,
a copy-able pull command, and a visible publisher identity. Publishing should
take a repository, one workflow file and one pull request, not a conversation
with the registry maintainers.

This ADR is a proposal. Nothing here is implemented, and no third-party
namespace exists.

## Context

Today exactly one workflow can sign a pack: this repository's
`.github/workflows/publish.yml` on `refs/heads/main`. The built-in client trust
accepts that identity (and, until 2026-11-06, the former `mvm-templates`
identity) for the legacy `agent/` and `runtime/` namespaces only. ADR-055
requires that community namespaces get their own explicit publisher trust, that
no wildcard conveys official status, and that a valid signature says who
published a pack and that it is unchanged, not that it is safe. A repository
rename changes the keyless identity, so it is a trust rotation.

`publish.yml` also builds every changed source under `pack-sources/` on push
and on a 12-hour schedule, signs it, and commits `index.json` and `packs/`.
There is no step that downloads an application archive and checks it against
its descriptor (ADR 001, section 1).

## Decision

### 1. Namespace is the GitHub owner

A third-party pack is `owner/name@version`, where `owner` is the lowercase
GitHub login of the user or organisation that owns the publishing repository.
`mvm`, `agent` and `runtime` are reserved. A namespace is claimed by the first
accepted publisher entry (section 3) and cannot be transferred except by a new
entry reviewed the same way. Owner or repository rename is a trust rotation:
the old entry stays, the new identity needs a new entry.

### 2. The author's repository builds and signs

The author's repository contains the same source layout as `pack-sources/`: a
`pack.toml`, plus either `pack/` (a policy pack) or an `[application]`
descriptor (ADR 001). A tag push runs a workflow in that repository that
produces `manifest.json` and a keyless `manifest.sigstore.json`, using the
repository's own OIDC identity, and attaches both to the GitHub release for the
tag. The registry offers a reusable workflow and a template so the author's
workflow is a few lines. The signature identity is the author's workflow, never
the registry's.

Application archives stay release assets of the author's repository, as in
ADR 001; git carries only the descriptor.

### 3. A publisher entry is the only thing reviewed

An author opens a pull request adding one file, `community/publishers/<owner>.toml`:

```toml
repository = "owner/repo"
workflow   = ".github/workflows/publish-pack.yml"
ref         = "refs/heads/main"   # one exact ref, no pattern
environment = ""   # optional GitHub environment, empty for none
packs      = ["name", "other-name"]
```

The fields mirror what keyless identity binds (issuer is always GitHub
Actions): repository, workflow and ref. The ref is one exact
branch or tag, never a pattern: the client matches exact signing identities, so
the author's workflow signs from a fixed ref (for example `refs/heads/main`) and
attaches the signed files to the release for the version in `pack.toml`. The
trusted identity then stays the same across releases. nono accepts tag patterns
server-side; this registry does not, to avoid pattern matching in the client. Review checks namespace ownership
(the opener controls the repository), name collisions and impersonation, not the
software. The entry grants indexing, nothing else.

### 4. The registry indexes; it does not re-sign and does not run author code

A registry workflow, on a schedule and on manual dispatch, reads each publisher
entry, lists new tagged releases, and downloads only data: `manifest.json`,
`manifest.sigstore.json` and, for policy packs, the listed `files/`. For each
version it:

1. verifies the signature identity equals the publisher entry (repository,
   workflow, ref) and the GitHub OIDC issuer;
2. runs the same validation as first-party packs (`validate-packs.py`);
3. for an application, downloads the archive and checks size and SHA-256
   against the descriptor before indexing; a failure blocks the version;
4. copies the manifest and signature bytes verbatim under `community/packs/` and
   adds the exact-byte `manifest_sha256` pin to `community/index.json` (see
   Community index below); it never signs them.

The registry never executes anything from the author's repository and never
runs on a `pull_request_target` with author code. Published bytes are
immutable: a tag whose manifest bytes change after indexing is refused and
flagged, not re-indexed.

### 5. Trust stays with the consumer

Indexing is discovery. A client trusts a third-party namespace only when the
user adds the publisher (repository, workflow, ref) to their trust policy, or
when a future client release ships a reviewed default. Bundle keys remain the
separate root described in ADR 001, section 2: the descriptor names a `key_id`
and does not enroll it. Pages label packs `official` (first-party identity) or
`community` (third-party), and always show the signing identity.

### 6. Revocation

The author can revoke their own versions through a pull request that appends to
`revocations.toml` (by manifest SHA-256 or exact identity, as today). The
registry maintainers can revoke any entry, including a whole publisher
(takedown for malware or impersonation). Revocation is append-only and already
signed into the short-lived feed.

### 7. Limits

- One `guest_arch` per application descriptor (ADR 001), so a multi-architecture
  pack is one version per architecture until the schema changes.
- A size cap on policy `files/`; application archives are only subject to the
  archive check in section 4.
- Per-publisher rate limit on new versions per day.

## Consequences

- Publishing needs no registry credentials and no maintainer action per
  release, only per new publisher.
- The registry's signing authority does not widen: it still signs only its own
  first-party packs. A compromised third-party repository can publish bad
  versions of its own packs, not another namespace's.
- The index grows with third-party packs, so `index.json` needs a publisher
  field and the pages need the official/community distinction; likely index
  schema v3.
- `publish.yml` must gain the archive check (section 4, step 3) before any
  application, first-party or not, is indexed.

## Community index: references, not packs

Community packs are listed in a separate root, `community/index.json`, and are
never in the official `index.json`. The registry does not host, build or sign a
community pack. An author's whole contribution is a reference to a pack their
own repository already signs and releases (Decision 2).

**The reference.** One pull request adds `community/publishers/<owner>.toml`
(Decision 3): repository, workflow, one exact ref and the pack names it may list.
That is the only reviewed change. No pack source, payload or archive is added
to this repository.

**The index.** A registry workflow resolves each reference (Decision 4) and
writes `community/index.json`: for every verified release, the pack name,
version, the author's `manifest.json` and `manifest.sigstore.json` URLs, and the
`manifest_sha256` of the exact manifest bytes. It also keeps a verbatim copy of
those two small files (never an application archive) so validation and the
generated pages work offline. Application archives stay release assets in the
author's repository and are read back and checked against the descriptor
before a version is listed.

**Trust.** The index is discovery only and is not signed. Listing says nothing
about safety. A client installs a community pack only after the user trusts the
author's signing identity (repository, workflow, ref); a namespace in the
community index never inherits the registry's built-in trust. The registry
identity signs nothing community, so a community pack can be delisted or
revoked by identity without touching official packs. The reserved namespaces
`mvm`, `agent` and `runtime` cannot appear in the community index.

**Index schema.** The community index needs a publisher block (repository,
workflow, ref) and manifest URLs per version, which the official
schema v2 does not carry. It is a new schema version, and the client must
parse it before any community pack can be pulled. That client work is tracked
in the `mvm` repository; until it ships, community entries are listed on the
pages but not installable with `mvmctl`.

**What this replaces.** The reviewed submission flow (`docs/publishing-a-pack.md`,
`just new-pack`) puts an author's source in this repository, where the registry
workflow signs it under the identity clients trust by default for `agent/` and
`runtime/`. That is not a community path. It remains only for packs the
maintainers accept as first-party, with `mvm`, `agent` and `runtime` reserved
(`new-pack.py` and the maintainer check), and should be retired for community
submissions once the reference flow exists.

## Prior art

How the registries we are matching actually work (read from their docs on
2026-11-05):

- **nono** (registry.nono.sh) hosts uploaded files. The author logs in with
  GitHub, creates the pack, and registers a trusted publisher: repository,
  workflow path, ref pattern and optional environment. The namespace must equal
  the publishing GitHub org. The author's workflow signs keyless and exchanges
  a GitHub OIDC token for a short-lived upload token. On pull, the client
  verifies the Sigstore bundles, checks that the signer's org matches the
  namespace, and pins the signer in a lockfile. A reusable workflow reports its
  own path as the signing identity, so each pack inlines its workflow.
- **smolmachines** pushes to any OCI registry (`smolvm pack push ... ghcr.io/you/x:v1`)
  and keeps `library/` for official entries. Its docs do not describe third-party
  listing.

This ADR keeps the author-hosted side (a reference, not an upload) and takes
nono's identity binding:

- The namespace equals the GitHub owner of the signing repository, and the
  client refuses a pack whose signer owner differs (Decision 1).
- The signer identity is pinned in a client lockfile on first pull; a different
  signer for the same pack is an error, not an update.
- The author's workflow is inlined in the author's repository. The version is
  `pack.toml`'s semver, and the tag only triggers the run.
- A trusted-publisher entry has an optional `environment`, as in nono.

## Open questions

- **Reusable-workflow identity.** nono reports that a reusable workflow's
  signing identity is the called file, not the caller, which is why it inlines
  workflows; confirm with a test run here. If the author's workflow calls a registry
  reusable workflow, which workflow ref appears in the signing certificate: the
  caller or the called one? The publisher entry format depends on this. Needs
  a test signing run, not an assumption.
- **Archive check without `mvmctl`.** The registry can verify digest and size
  with the standard library. Verifying the bundle signature against `key_id`
  needs a compatible signed `mvmctl` release; until then the check is
  integrity only.
- **Default client trust.** Whether any third-party publisher is ever trusted
  by default, and who decides.
- **Takedown and dispute policy** beyond revocation.
- **Distribution rights.** The registry cannot establish that an author may
  redistribute the bytes in their archive (ADR 001 raises the same for Claude).

## Follow-ups

1. Done: the archive read-back before signing (#100). The community intake runs
   the same check before listing an application version.
2. Run a test keyless signing from a throwaway repository to settle the
   reusable-workflow identity question.
3. Define `community/publishers/<owner>.toml`, its validator and tests.
4. Add the intake workflow that resolves references into `community/index.json`
   and an author-facing guide (`docs/publishing.md`).
5. Extend the generated pages with a Community section and the author's
   signing identity.
6. New index schema version and the matching `mvm` client work (community
   root, per-identity trust), tracked in the `mvm` repository.
7. Retire the in-repo submission flow for community packs.
