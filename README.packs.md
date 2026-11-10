# The pack registry

This repository is the signed pack registry `mvmctl` talks to. A pack
ships machine-readable policy — a profile (`pack/profile.toml`), a group
(`pack/group.toml`), or both — plus any payload files the manifest declares,
signed keyless by the publish workflow.

The sole catalog is [`index.json`](index.json), schema v2. Each `versions` entry
contains `version` and the lowercase `manifest_sha256` of the exact published
manifest bytes. It lists all published versions, not unpublished source intents
or support guarantees. The supported pack is the application
`agent/claude@2.0.1`; the legacy policy-only packs remain discoverable. The index is not a signed trust document: clients verify each pack's
`manifest.json` against its adjacent `manifest.sigstore.json`.

## Application descriptors

Publisher tooling also supports a distinct signed application manifest (outer
schema v2, `kind = "application"`). It points to a prebuilt `.mvmpkg`; it is
not a policy group. This source-only support does not
claim a published application, a released compatible client, or a successful
pull/install/run witness.

Schema v2 describes the **existing complete boot bundle**, not a portable
application-only component. [ADRs 004–006](docs/adr/006-runnable-composable-packs.md)
propose a new, versioned component format and selectable base; the registry
does not publish such a component yet. Do not interpret the existing
`agent/claude@2.0.1` descriptor or any legacy policy-only version as that
new format.

A [draft schema-3 application-only descriptor/source contract](docs/portable-application-component.md)
has strict parser and structural validation, but is blocked from signing and
publication pending agreement with the `mvm` format owner and a compatible
archive/consumer gate.

An application source consists only of `pack.toml`, with no `pack/` payload.
For example, this is a **synthetic, non-publishable test definition**, not a
real software release:

```toml
version = "1.0.0"
description = "Synthetic app descriptor"

[application]
schema_version = 1
guest_arch = "aarch64"

[application.bundle]
source = "https://bundles.example/test/hello/1.0.0/app.mvmpkg"
archive_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
archive_size = 123
key_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
```

Folder coordinates and `version` determine the exact `namespace/name@version`
reference. The resulting manifest contains exactly `schema_version`, `kind`,
`reference`, `description`, and `application`. The published version contains
only `manifest.json` and `manifest.sigstore.json`, never `files/`.
The nested application schema is v1; the discovery index remains schema v2.
Existing policy manifest-v1 bytes are unchanged.

The descriptor binds the archive SHA-256, positive byte size, supported guest
architecture (`x86_64` or `aarch64`), and expected bundle key ID. Source locators
must be canonical HTTPS without credentials/query/fragment, or a digest-pinned
OCI reference. A descriptor does **not** enroll its named key in a trust store.
Consumers must authenticate the descriptor under namespace publisher policy,
enforce revocation, and independently verify the bundle through existing trust
and admission checks. No official vendor namespace or redistribution permission
is granted by this schema.

## Layout

Every currently supported new application pack must embed its application
binary in a signed complete `.mvmpkg`; a policy alone cannot be signed, and
built-image packs are not part of this registry. A pack source is a single
`pack-sources/<namespace>/<name>/pack.toml` with an `[application]` bundle (see above).
The legacy policy-only versions under `packs/` stay immutable and are not rebuilt.

The [native input record](docs/application-packages.md) preserves inspected archive and
executable pins without defining a second application descriptor or claiming a published
runnable environment.

## Publishing

Merging to `main` runs `.github/workflows/publish.yml` when `pack-sources/`
changes. It builds manifests (SHA-256 and size per file), signs each manifest
keyless with `cosign sign-blob` while the run's OIDC identity is
`refs/heads/main`, validates the layout with `scripts/validate-packs.py`,
and commits `index.json` and `packs/`. Published versions are immutable: change a source and
the build refuses until the version in `pack.toml` is bumped. The push and
scheduled runs publish the catalogue and signed application descriptors.

The ordinary publisher continues to publish a repository-local revocation
feed under `packs/revocations.json`, signed by the pack publisher identity.
That legacy feed is not the official MVM revocation root and must not be used
to establish `mvm/` pack status.

Official MVM packs use the separate `.github/workflows/registry-pack-revocations.yml`
producer. Its inspectable source is `revocations.toml`: add an exact signing
identity to `revoked_identities` or a lowercase manifest SHA-256 to
`revoked_manifests`. Entries are append-only. The feed is published to the
`registry-pack-revocations` GitHub release as `revocations.json` and
`revocations.sigstore.json`; immutable numbered pairs
`revocations-<sequence>.json` and `revocations-<sequence>.sigstore.json` form
the verifiable sequence history. Clients read only the two alias assets. To keep
the live release under GitHub's 1000-asset cap, the manually dispatched
`registry-pack-revocations-archive.yml` workflow copies the oldest signed pairs to an
archive release (`registry-pack-revocations-archive-<first>-<last>`), checks every byte
reads back, then removes them from the live release; the live history stays
contiguous from its first retained sequence and is re-verified end to end. The
official signer is exactly

```
https://github.com/tinylabscom/mvm-packs/.github/workflows/registry-pack-revocations.yml@refs/heads/main
```

under the GitHub Actions OIDC issuer. A separate read-only OIDC signing job
and contents-write publishing job verify the signed candidate and read back
the release. The schedule refreshes every 12 hours; new signed documents are
valid for 36 hours, and clients reject them at `not_after`. Each signing and
publishing job is bounded to 15 minutes. Previously published, immutable
30-day documents remain verifiable as history; they are not re-signed as new
candidates or silently converted to shorter-lived bytes. Initial
publication requires an explicit manual dispatch authorization. The producer
refuses to bootstrap from an existing but invalid or incomplete release.

The distinct release identity can also be explicitly configured as an operator
feed authority for a non-`mvm/` application, provided it differs from that
application's authenticated publisher. New 36-hour documents fit the client's
48-hour operator maximum. This does not extend the built-in official namespace
trust to other namespaces or enroll trust automatically. A new candidate or
unsigned orphan exceeding the new issuance window is refused, even when it
would be valid as historical official data.

If the first bootstrap fails after creating the public release but before
uploading any assets, recovery is deliberately manual. A maintainer must verify
that the release has zero assets and that no signed feed was published or
consumed, then remove only that empty release and its tag before retrying the
authorized bootstrap. Never delete a release containing any revocation assets;
a partial or nonempty release requires investigation and authenticated history
recovery rather than another bootstrap.

GitHub release assets are mutable storage, not a cryptographic append-only
log. The workflow verifies every retained numbered signature, contiguous
sequence, and append-only revocation set, but cannot detect removal of an
entire valid suffix if the release is rewritten to an older valid prefix.
Clients must persist their own authenticated sequence high-water mark and fail
closed on rollback. The producer's pinned identity is not silently rotatable:
annual or compromise rotation requires an explicitly reviewed client trust
update and at least 14 days of dual-signed overlap for identical feed bytes.
This workflow does not yet publish dual-signed rotation bundles; do not rotate
or replace its signer until that implementation is reviewed and compatible
clients are released.

An invalid, missing, expired, rolled-back, or unverifiable feed is unavailable
trust data, not an empty revocation list. Producer publication alone does not
make clients enforce revocation; consumers must fetch or receive the feed,
verify its exact identity, persist a rollback-resistant checkpoint, and apply
it on installation and every subsequent use.

Clients verify on every use — pull, and every policy load — against the
publisher trust policy. New packs are signed under this workflow's identity:

```
https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main
```

under the GitHub OIDC issuer. The nine versions published before the repository
rename retain their original, verified signature bundles so released clients
can continue to pull them. Their manifest digests are pinned in the publisher;
new content cannot claim the former identity. The built-in MVM policy accepts
the former exact workflow identity for these legacy namespaces only until
2026-11-06 00:00 UTC, then rejects it. A controlled re-signing under the
current identity must be published before that cutoff; until then, the build
preserves verified historical signatures. An operator policy at
`$MVM_HOME/registry/publishers.toml` replaces built-in trust wholesale.

The publisher validator checks every included file and verifies each bundle
under the current identity, or under the former identity only for the pinned
historical manifests before the cutoff. A valid signature proves publisher
identity and content integrity, not that a workload is safe. No `mvm/` pack is
published or labelled official here.

Use `python3 scripts/validate-packs.py --verify-signatures --require-revocations`
to validate a published checkout and its live revocation signature. The plain
validator permits a checkout predating the feed, but refuses a partial feed or
an expired feed when one is present. Do not treat an old checkout without the
feed as revocation-aware.

## Using a pack

```sh
mvmctl search                                # what the registry offers
mvmctl pull agent/claude                      # verify, install, pin (latest: 2.0.1)
mvmctl pack info agent/claude                 # signer, key, signed policy
```

A pack composes where its reference sits in the `--policy` order; the
signature is re-verified on every load and the manifest digest is pinned in
`$MVM_HOME/registry/packs.lock.toml`.
