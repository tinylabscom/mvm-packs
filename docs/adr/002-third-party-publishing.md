# ADR 002: Third-party pack publishing

Status: proposed
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

An author opens a pull request adding one file, `publishers/<owner>.toml`:

```toml
repository = "owner/repo"
workflow   = ".github/workflows/publish-pack.yml"
ref_pattern = "refs/tags/v*"
packs      = ["name", "other-name"]
```

The fields mirror what keyless identity binds (issuer is always GitHub
Actions): repository, workflow and ref. Review checks namespace ownership
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
4. copies the manifest and signature bytes verbatim into `packs/` and adds the
   exact-byte `manifest_sha256` pin to `index.json`.

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

## Open questions

- **Reusable-workflow identity.** If the author's workflow calls a registry
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

1. Add the archive check to the publisher path (also required by ADR 001).
2. Run a test keyless signing from a throwaway repository to settle the
   reusable-workflow identity question.
3. Define `publishers/<owner>.toml`, its validator and tests.
4. Add the intake workflow and an author-facing guide (`docs/publishing.md`).
5. Extend the generated pages for the official/community label and publisher
   identity.
6. Index schema change and matching `mvm` client work, tracked in the `mvm`
   repository.
