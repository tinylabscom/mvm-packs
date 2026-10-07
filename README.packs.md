# The pack registry

This repository is also the signed pack registry `mvmctl` talks to. A pack
ships machine-readable policy — a profile (`pack/profile.toml`), a group
(`pack/group.toml`), or both — plus any payload files the manifest declares,
signed keyless by the publish workflow.

## Layout

Sources live under `pack-sources/<namespace>/<name>/`:

```
pack-sources/runtime/python/
├── pack.toml          # version = "1.0.0", description = "..."
└── pack/
    └── group.toml     # the policy document (profile.toml also allowed)
```

Image-bearing packs are not publishable yet. The current schema v1 `[image]`
field identifies signed image *source* (`mvm.toml`, `flake.nix`, `flake.lock`),
not a built root filesystem. It cannot bind a built image digest, the base
image-set pin, or build provenance. `build-packs.py` rejects any source with
`[image]`, and `validate-packs.py` rejects any published manifest with an
`image` field. No image pack should be described as ready to run on this
publisher path.

The next image release contract needs a built-image digest and size, a base
image-set identity (`repository`, `release_tag`, and signed root-manifest
SHA-256), and a verifiable provenance attestation bound to the same image and
publisher identity. Pack CI must build from the base set pinned by MVM's
`images.lock`, compare two independent output byte streams, and only then sign
the image and descriptor. The client must reject a base identity that its own
lock does not accept and verify the image, descriptor, and attestation before
installation or execution. These producer and client changes are not shipped
by the current schema; the source-only guard is a release safety check, not
evidence that image signing or reproducibility exists.

An offline producer check is available as `scripts/reproduce-app-layer.py`.
Supply a complete, trusted, quiescent staged application tree, the exact `mvmctl` binary to run,
an independently obtained SHA-256 for that binary, and a new output directory:

```sh
python3 scripts/reproduce-app-layer.py --help
```

The check copies the selected executable through a no-follow descriptor into
private storage, verifies the copy against the supplied digest, and invokes
only that copy for both `mvmctl image build-layer` runs. It builds in separate
private directories, verifies the three filesystem assets against
each build's `asset-report.json`, compares all output bytes, and atomically
publishes the first result without replacing an existing path. Its output is
unsigned. It does not prove a base-image pin, build provenance, or official
pack status, and it does not make image-bearing packs publishable.
Do not modify the staged tree while either build runs: this check does not
provide a race-safe source snapshot or establish reproducibility if source
files change concurrently.

Source authors can validate the proposed built-image descriptor shape with
`scripts/build-packs.py`, but the command still refuses to publish any
image-bearing pack before it signs or writes one. Even when the descriptor
passes its shape checks, the command exits nonzero with a deliberate
`not publishable` refusal; that exit is not a successful build. This is a
source descriptor with `schema_version = 2` inside `[image]`; it is **not** a
published manifest schema v2. It requires `platform` (`linux/x86_64` or
`linux/aarch64`), a `base_set` table naming `tinylabscom/mvm-images`, its
immutable image-set release tag (for example, `image-set/v0.2.4`) and
root-manifest SHA-256, and a `release` table naming `tinylabscom/mvm-packs`
with the deterministic tag derived from its pack reference (for example,
`pack-runtime-python-v1.0.0`). The `assets` table requires seven external
release assets: `rootfs.ext4`, `rootfs.verity`, `rootfs.roothash`,
`mvm-meta.json`, `rootfs.signature.json`, `provenance.json`, and
`provenance.signature.json`. Each records its fixed name, lowercase SHA-256,
and positive byte size. Extra fields, arbitrary URLs, unsafe names, missing
attestation references, and source-only schema-v1 images are refused. These
checks validate metadata shape only; they do not download, verify, sign, or
publish any image or attestation. The existing nine schema-v1 policy packs
continue to publish unchanged.

`scripts/verify-base-set.py` checks a pre-downloaded base set locally. It
requires a source `pack.toml`, the exact `image-set.json` and
`image-set.json.bundle` release files, and an artifact directory containing
only the default-tenant kernel, root filesystem, verity tree, and root hash
for the declared architecture. It also requires an explicit `mvmctl` binary
and its independently supplied SHA-256. The command invokes `mvmctl image
boot verify` with the binary's compiled image lock, four selected artifacts,
`--require-complete`, and JSON output; it checks the reported role, target,
name, digest, size, release tag, and signed root digest against the source
descriptor and local files. Run `python3 scripts/verify-base-set.py --help`
for its exact arguments. A successful check does not verify unselected image
members or current revocation status. The later image composer must rehash the
same files when it opens them; this earlier check is not a time-of-use
guarantee. CI must pin the verifier digest outside pack source, and this
command is not wired into publication until a released verifier supports
selected-artifact checks. It does not make an image pack publishable.

The workflow builds the published layout under `packs/`:

```
packs/index.json                                  # registry index (mvmctl search)
packs/<ns>/<name>/<version>/manifest.json         # RegistryPackManifest, schema v1
packs/<ns>/<name>/<version>/manifest.sigstore.json# detached cosign bundle
packs/<ns>/<name>/<version>/files/...             # payload, digest-pinned by the manifest
packs/revocations.json                              # short-lived revocation document
packs/revocations.sigstore.json                     # detached release-identity bundle
```

## Publishing

Merging to `main` runs `.github/workflows/publish.yml` when `pack-sources/`
changes. It builds manifests (SHA-256 and size per file), signs each manifest
keyless with `cosign sign-blob` while the run's OIDC identity is
`refs/heads/main`, validates the layout with `scripts/validate-packs.py`,
and commits `packs/`. Published versions are immutable: change a source and
the build refuses until the version in `pack.toml` is bumped. This workflow
currently publishes policy packs only, not prepared images.

The same workflow publishes a separate registry-pack revocation feed. Its
inspectable source is `revocations.toml`: add an exact signing identity to
`revoked_identities` or a lowercase manifest SHA-256 to `revoked_manifests`.
Entries cannot be removed by a later release. A scheduled run refreshes the
document every 12 hours, advancing its positive sequence and setting a 36-hour
validity window. The sign job first verifies the previous document under the
current release identity, then signs the new document. The separate
contents-write job verifies the downloaded signature and checks exact sequence
advancement against the checked-out publication before committing. The feed
uses the existing publish workflow identity; it does not change that identity.
An invalid, missing, expired, rolled-back, or unverifiable feed must be treated
as unavailable trust data, not as an empty revocation list. This publisher
change alone does not make clients enforce revocation; a client must fetch,
verify, checkpoint, and apply the feed on install and every run before it can
claim that guarantee.

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
mvmctl pull agent/claude@1.0.0               # verify, install, pin
mvmctl run --policy agent/claude -- make test
```

A pack composes where its reference sits in the `--policy` order; the
signature is re-verified on every load and the manifest digest is pinned in
`$MVM_HOME/registry/packs.lock.toml`.
