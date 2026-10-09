# The pack registry

This repository is also the signed pack registry `mvmctl` talks to. A pack
ships machine-readable policy — a profile (`pack/profile.toml`), a group
(`pack/group.toml`), or both — plus any payload files the manifest declares,
signed keyless by the publish workflow.

## Layout

Sources live under `pack-sources/<namespace>/<name>/`:

```
pack-sources/runtime/python/
├── pack.toml          # version = "1.1.0", pinned image-build intent
└── pack/
    └── group.toml     # the policy document (profile.toml also allowed)
```

No image-bearing pack is published yet. The current schema v1 `[image]`
field identifies signed image *source* (`mvm.toml`, `flake.nix`, `flake.lock`),
not a built root filesystem. It cannot bind a built image digest, the base
image-set pin, or build provenance. `build-packs.py` rejects any source with
`[image]`. A built schema-v2 descriptor passes registry validation only after
publisher-signature and public release byte/signature verification; the normal
publisher defers `[image_build]` without signing or publishing it. The existing
signed `runtime/python@1.0.0` policy pack remains available while the
`runtime/python@1.1.0` image intent awaits a measured release. No image pack
should be described as ready to run on this path.

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

The first planned runnable environment is Claude Code. Its
[delivery plan](CLAUDE-ENVIRONMENT.md) links the SDK, terminal/authentication and
publication issues and defines the release evidence. It is not a published image
or a replacement for the existing policy-only `agent/claude` pack.

### Advancing the base-image lock

A published pack version is immutable, including its base-set tag and signed
root-manifest digest. When MVM advances `images.lock` to a base set that no
longer accepts a pack's recorded pin, that pack version stays available for
clients whose lock still accepts it, but new clients must refuse both pull and
launch. Do not rewrite, re-sign with changed bytes, or silently rebuild the
existing version against the new base set. Build and reproduce a new pack
version against the new lock, sign its new image, descriptor, and provenance,
then publish it under a new versioned release tag. A client upgrade does not
implicitly select that new version: operators must pull and pin it explicitly.
The consumer and publisher gates described here are not yet implemented for
image-bearing packs; this is the compatibility rule they must enforce.

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

An image producer starts with `[image_build]` in `pack.toml`. This is build
intent, not a registry descriptor: it records `schema_version = 1`, `platform`,
`base_set`, and `release`, without claiming digests or sizes for assets that
have not yet been built and signed. `verify-base-set.py`,
`bind-image-candidate.py`, and `compose-pack-image.py` consume that intent.
`build-packs.py` defers it without touching the registry. The separate image
publisher generates the final `[image]` from measured, signed outputs only
after rechecking the published release.

The generated built-image descriptor has `schema_version = 2` inside
`[image]`; it is **not** a published manifest schema v2. It requires
`platform` (`linux/x86_64` or
`linux/aarch64`), a `base_set` table naming `tinylabscom/mvm-images`, its
immutable image-set release tag (for example, `image-set/v0.2.4`) and
root-manifest SHA-256, and a `release` table naming `tinylabscom/mvm-packs`
with the deterministic tag derived from its pack reference (for example,
`pack-runtime-python-v1.0.0`). The `assets` table requires seven external
release assets: `rootfs.ext4`, `rootfs.verity`, `rootfs.roothash`,
`mvm-meta.json`, `rootfs.signature.json`, `provenance.json`, and
`provenance.signature.json`. Each records its fixed name, lowercase SHA-256,
and positive byte size. Extra fields, arbitrary URLs, unsafe names, missing
attestation references, and source-only schema-v1 images are refused.
`build-packs.py` validates a supplied `[image]` but still refuses its
publication. The existing nine schema-v1 policy packs continue to publish
unchanged.

`scripts/verify-base-set.py` checks a pre-downloaded base set locally. It
requires a source `pack.toml` with `[image_build]`, the exact `image-set.json` and
`image-set.json.bundle` release files, and an artifact directory containing
only the default-tenant kernel, root filesystem, verity tree, and root hash
for the declared architecture. It also requires an explicit `mvmctl` binary
and its independently supplied SHA-256. It invokes a private, SHA-checked copy
so replacing the selected path cannot change the verifier after the check.
The command invokes the pinned verifier's `image boot verify` command with its
compiled image lock, four selected artifacts,
`--require-complete`, and JSON output; it checks the reported role, target,
name, digest, size, release tag, and signed root digest against the source
descriptor and local files. Run `python3 scripts/verify-base-set.py --help`
for its exact arguments. A successful check does not verify unselected image
members or current revocation status. The later image composer must rehash the
same files when it opens them; this earlier check is not a time-of-use
guarantee. CI must pin the verifier digest outside pack source, and this
command is not wired into publication until a released verifier supports
selected-artifact checks. It does not make an image pack publishable.

`scripts/bind-image-candidate.py` combines the two offline checks without
publishing an image pack. Give it a source `pack.toml` with `[image_build]`, the exact
pre-downloaded signed root files and four selected base artifacts, the
reproduced application-layer directory, an independently supplied SHA-256
for a released `mvmctl`, and a new output directory. Run
`python3 scripts/bind-image-candidate.py --help` for the exact flags. It
copies every input through no-follow file descriptors into private staging,
checks the base copy with the existing verifier, validates the copied layer
against its asset report, and atomically publishes those copies with a
deterministic `candidate.json` recording their digests and sizes. The
descriptor marks itself as an unsigned candidate and states that verification
covered only the selected base artifacts. Keep all inputs quiescent while
they are copied; this is not a race-safe snapshot of mutable source paths.
The candidate is neither signed nor attested and closes no image-pack release
acceptance criterion. A released verifier, image signing and attestation,
and client pull, admission, and boot verification remain necessary before an
image-bearing pack can be published or presented as official. The binding
step does not establish a time-of-use guarantee or current revocation status.

`scripts/compose-pack-image.py` is an offline, unsigned composition check for
that candidate. Run it inside the project builder VM with `--candidate`, the
versioned `--reference`, the same released `--mvmctl` and independently pinned
`--mvmctl-sha256`, and a new `--output` directory. The command snapshots the
candidate through no-follow descriptors, rechecks its recorded bytes, and
re-runs the released verifier against the signed selected base files. It then
extracts the base and application ext4 images with `debugfs`, adds application
entries without replacing base entries or accepting application symlinks or
special files, and builds the combined tree twice with the pinned client's
`image build-layer` command. It refuses to publish the output directory if any
of the three filesystem assets or the asset report differ byte-for-byte.
The output contains those four files and `composition.json`, marked
`unsigned-composed-image`, binding the copied candidate digest, base-set pin,
layer digest, verifier digest, and composed asset digests. Run
`python3 scripts/compose-pack-image.py --help` for the exact invocation.
The source images must remain quiescent while the initial private snapshot is
copied. This check has not been exercised against a released verifier or a
real published base image yet; it does not generate `mvm-meta.json`, sign an
image or descriptor, attest provenance, establish revocation freshness, or
make an image pack publishable. The existing publisher refusal remains in
force.

`scripts/sign-composed-image.py` prepares signed *evidence* for a later image
release; it is not wired into the publisher. It accepts the composed directory,
the exact `candidate.json` that produced it, a versioned pack reference, its
`[image_build]` pack source, a `mvm-meta.json` beside that source, and a new
output directory (`--composition`, `--candidate-report`, `--reference`,
`--pack-source`, `--mvm-meta`, `--output`). It also requires
`--mvm-images-lock` naming the `images.lock` file
from an independently pinned mvm checkout. It snapshots input files without
following symlinks, refuses a composed base set that differs from that lock's
current signed-root pin, and records the lock-file SHA-256 in provenance. When
mvm advances its base lock, an old candidate cannot be signed as a new release:
rebuild against the new base, or keep the existing release immutable. This
local comparison does not authenticate the mvm checkout; the future publisher
must pin its source commit independently. The helper rechecks
the composition and asset-report digests, candidate/base bindings, and exact
pack source bytes. It rejects a boot sidecar without a sealed, known command
entrypoint, runtime overlay, supported libc and protocol, and real guest agent,
then binds that sidecar and the seven measured release assets into an
`image-descriptor.json` matching the consumer's schema-v2 image contract.
The sidecar's assertion about the guest still needs a live boot check before
publication. The helper
then writes an in-toto/SLSA v1 provenance statement naming the rootfs digest,
base-set pin, application layer, verifier digest, and publisher run. It signs
the rootfs, statement, and a separate image-evidence descriptor with cosign,
then verifies each bundle under the exact `publish.yml@refs/heads/main` OIDC
identity before atomically exposing the output. A different branch, workflow,
failed verification, or changed input leaves no output. The output explicitly
identifies itself as `signed-image-evidence-not-published`; it contains no
signed registry manifest. A publisher workflow must perform
the actual keyless signing in that identity, verify the complete image release
and client contract, and keep the existing image-publication refusal until
those gates are implemented. Unit tests mock cosign and do not establish an
actual signed image.

`scripts/stage-image-release.py` is the next fail-closed release-input gate.
Give it the signed evidence directory, exact versioned reference, matching
`[image_build]` source, the current `mvm/images.lock` from an independently
pinned checkout, and a new output directory; run `python3
scripts/stage-image-release.py --help` for the flags. It copies inputs without
following links, rehashes every evidence and descriptor asset, checks the
source intent, current base pin, sealed boot sidecar and provenance subject,
and verifies the rootfs, provenance and evidence bundles under the main
publisher workflow identity. It then stages the seven measured release assets
and descriptor without overwriting an existing path. Advancing the base lock
refuses this staging step for the old pin; a new pack version must be rebuilt
and signed. This command does not authenticate the caller-supplied mvm checkout,
upload a GitHub release, publish a registry manifest, or prove a live boot.
The image-publication refusal remains in force.

`scripts/upload-image-release.py` consumes the signed evidence through that
staging gate under the main `publish.yml` workflow identity. It requires the
workflow's `GITHUB_TOKEN` with release write permission and refuses an existing
versioned tag or release. It creates a draft release at the workflow's exact
source commit, uploads the eight staged assets (the seven image assets plus
`image-descriptor.json`), checks the remote asset names, sizes and any reported
SHA-256 values, downloads every asset and compares its bytes to the staged
copy, then verifies the tag target before publishing. A failed upload or
comparison leaves the release as a draft; it never overwrites a published
version. The command reads the published release back before reporting
success. It does not run automatically yet, does not publish the signed
registry manifest, and does not make the image pullable. The publisher must
still pin and authenticate its mvm checkout and released verifier, run the
builder-VM composition/signing workflow, wire this command into that workflow,
and verify the resulting live client path before lifting the registry guard.

Before a signed registry manifest can name an uploaded image, the producer
must independently recheck the published release. The
`upload-image-release.py` module's `verify_published` gate checks the main
publisher workflow identity, release tag and source commit, exact remote asset
metadata, every downloaded byte, and the tag target without modifying the
release. `build-packs.py` can serialize a measured schema-v2 descriptor into
the signed manifest shape. `scripts/publish-image-pack.py` is an explicit
keyless publication gate: it restages signed evidence against the current
independently supplied mvm base lock, rechecks the public release, copies the
source policy payload without following links, signs and verifies the manifest
under the main publisher workflow identity, then creates a new immutable
registry version without replacing an existing one. The validator refuses
built images unless publisher-signature verification is enabled; with it,
validation downloads and hashes every public release asset, verifies the
rootfs and provenance signatures and their image/base/source bindings, and
checks release metadata and tag target. The command is not wired into the
publisher workflow yet, so serialization or a local command run is not
evidence of a published pack or live client acceptance.

### Pack image composition v1

The build type named in that statement is the `compose-pack-image.py` operation
followed by `sign-composed-image.py` in the same publisher run. Its external
parameters are the exact versioned `reference` and the immutable `base_set`
(`repository`, `release_tag`, signed root-manifest SHA-256). Its internal
parameter is the SHA-256 of the verifier executable. The resolved dependencies
are the copied `candidate.json`, application-layer `rootfs.ext4`, signed
base root manifest and mvm `images.lock` by SHA-256, plus the publisher repository's exact git
commit. The publisher must obtain the base files
from the named release, verify them with the released verifier whose own
compiled `images.lock` accepts that base, reproduce the application layer,
bind the candidate, and compose the full rootfs twice before invoking the
signer. The statement's subject is the resulting `rootfs.ext4`; the Sigstore
certificate must identify the main publish workflow. This build type does not
claim a SLSA level while the publisher and consumer gates remain unfinished.

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
