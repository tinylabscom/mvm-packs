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

The `runtime/python@1.1.0` producer stages a real CPython 3.12 application
tree with `scripts/build-python-layer.sh` inside the Linux builder VM. The
current unpublished image intent targets `linux/x86_64`, matching the hosted
KVM runner used for its builder-VM staging lane; the flake retains an aarch64
package output for a future separately versioned image. The
wrapper invokes `scripts/stage-python-closure.py` with the pinned CPython
interpreter and exports a regular `python-tree.tar` artifact through the
builder shell-job output disk. Its
`pack-sources/runtime/python/image/flake.lock` pins the Nixpkgs revision and
content hash; the command refuses a lock update, queries the resulting Nix
store requisites, copies the complete closure without following links, and
adds `/bin/python3` as a guest link to the pinned interpreter. Staging reads
that executable's x86-64 ELF interpreter, requires its executable glibc
loader in the same closure, and adds `/lib64/ld-linux-x86-64.so.2` as a link
to that exact loader. An absent, unrecognized, or out-of-closure loader
refuses staging. The staged tree
is only input to the byte-identical layer rebuild above. It is not a signed
image, a published pack, or evidence of a successful boot.

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
entries without replacing base entries. It preserves relative symlinks whose
targets stay within the guest tree and absolute links into `/nix/store`, without
following either on the host; other absolute links, guest-root escapes, and
special files are refused. It builds the combined tree twice with the pinned client's
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

`scripts/build-python-image.py` is the builder-VM entry point for the
unpublished `runtime/python@1.1.0` x86_64 intent. Give it the checked-in
`pack.toml`, a verified released `mvmctl` binary and a separate file containing
that binary's lowercase SHA-256, the signed `image-set.json` and bundle, exactly
the four selected x86_64 base artifacts, the current `mvm/images.lock` from an
independently fetched mvm commit, and a new output directory. It refuses a
source base pin that differs from that lock before running Nix. Run
`python3 scripts/build-python-image.py --help` for the flags. It stages the
locked CPython closure, compares two application-layer builds byte-for-byte,
binds the selected base files with the released verifier, and compares two
complete composed images byte-for-byte. Only after rechecking the candidate
and composition bindings does it atomically export `candidate.json` and the
`composition/` directory. It must run inside the project Linux builder VM;
failures leave no exported directory. The output is unsigned candidate evidence,
not a pack release, attestation, signed descriptor, or boot witness.

The manual `Build unsigned Python image candidate` GitHub workflow supplies
that command with a signature-verified released Linux x86_64 client, the
current mvm `images.lock` fetched at a resolved main commit, and the selected
base assets from the pack's pinned image-set release. Its dispatch requires
the exact client release tag and archive SHA-256; the signed release checksum
and both Sigstore bundles are checked before the client runs. The job uses a
read-only repository token, has no signing identity, and uploads only a
short-lived artifact with the `unsigned-python-image-` prefix and numeric
workflow run ID suffix. The artifact is
not a GitHub release or a registry pack. A successful manual run and its
recorded digests are still required before any image-reproduction acceptance
is claimed.

The separate manual `Diagnose Python image with source client` workflow is a
read-only diagnostic while a compatible signed release is unavailable. It
pins one mvm source commit, compares that source client’s `images.lock` with
the current mvm main lock, builds a static x86_64 client on a hosted runner,
and runs the same unsigned producer inside the project Firecracker builder
VM. It uploads an unsigned candidate for three days without signing or
publishing anything. A source-built client is not a released-client witness;
this run cannot satisfy image publication or PS-06 acceptance.

`scripts/sign-composed-image.py` prepares signed *evidence* for a later image
release. The manual `sign_python_image` job in the main `publish.yml` workflow
verifies a release-tagged Linux x86_64 mvmctl archive and its signed checksum,
fetches the current mvm base lock and selected signed base assets, reproduces
the image inside the builder VM, and calls this signer under the main publisher
OIDC identity. It re-fetches the current base lock before and after signing
and uploads only a seven-day signed-evidence workflow artifact. The job
requires a source-adjacent sealed `mvm-meta.json`; runtime/python does not yet
have one, so it refuses before building. It does not upload an image release,
create a registry pack, or prove a live boot. No successful signed-image run
has been established.

Before signing, `scripts/check-python-base-entrypoint.py` snapshots the
selected rootfs, pack intent, and proposed sidecar without following links.
It requires the image-set/v0.2.4 rootfs digest and the exact
`/etc/mvm/entrypoint` bytes observed in that signed base, then requires the
sidecar to declare the actual `/bin/sleep infinity` boot argv. A different
base lock or changed marker refuses until a new base-specific rule is
measured and reviewed. This gate does not prove the composed image boots,
that Python runs through the declared command path, or that the sidecar's
libc declaration is correct; those remain live publication checks.

After the signer creates its private evidence snapshot, the publisher runs
`scripts/check-python-composed-runtime.py` against the copied `rootfs.ext4`
and `mvm-meta.json` before the evidence artifact can be uploaded. The check
requires the sidecar to declare glibc, follows the composed `/bin/python3`
links inside the ext4, reads the final Python ELF interpreter, and requires
the same executable x86_64 glibc loader behind the composed `/lib64` link.
Missing, mismatched, malformed, or non-executable members refuse the lane.
It also requires the final `/init` and `/etc/mvm/entrypoint` bytes to match
the measured signed base, requires the sidecar's boot argv to match that
entrypoint, and refuses an alternate `/etc/mvm/boot` that would override it.
Synthetic ext4 tests cover this check; a real hosted x86_64 builder run and
live boot remain necessary before publication acceptance.

The signer accepts the composed directory,
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
local comparison does not authenticate the mvm checkout; the manual signing
job resolves a current mvm main commit when fetching the lock. The helper rechecks
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
signed registry manifest. The manual job can sign only after its release and
boot-sidecar prerequisites are met. Release verification, live boot, and
registry publication remain separate gates. Unit tests mock cosign and do not
establish an actual signed image.

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
success. It is not wired into the signing job, does not publish the signed
registry manifest, and does not make the image pullable. A separate publication
lane still needs a truthful live boot check, release and registry readback,
and a released-client witness before lifting the registry guard.

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
