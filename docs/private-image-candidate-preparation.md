# Private image candidate preparation (code only)

`scripts/publish-image-pack.py --pack-source pack-sources/runtime/python
--evidence <signed-image-evidence-directory> --mvm-images-lock <current-lock>
--private-output <new-directory-inside-this-checkout>` prepares **unsigned**
registry bytes. It does not sign, upload, create a tag, change the registry
index, or contact GitHub. This is not an observer verdict or publication.

The existing image stager snapshots and independently checks the exact signed
evidence inventory, rootfs/provenance/evidence bundles against the existing
publisher identity, source intent and source bytes, composition verifier pin,
public release descriptor and current base lock. The shared registry renderer
produces the existing manifest schema, public origin and payload digests. No
author-provided manifest or new signing API is accepted. Metadata snapshots are
limited to 1 MiB; pack payloads are limited to 4096 entries and 64 MiB.
Public and private source metadata are parsed only from bounded no-follow,
nonblocking regular-file snapshots. Descriptor metadata uses the same snapshot
rule. Private output ancestors are captured with no-follow directory handles;
output staging and no-clobber publication use fd-relative operations, not a
resolved-path check followed by writes through the original path. Unsupported
directory/security primitives fail closed.
The shared stager also bounds evidence metadata and source/lock snapshots to
1 MiB before parsing. Large rootfs/verity image streams are separate from this
metadata limit; their existing evidence, asset digest and signature gates are
unchanged.

Output layout:

```text
candidate/
  registry/
    manifest.json                 # unsigned, existing canonical renderer
    files/pack/...                # exact payload covered by manifest
    files/<asset.name>            # seven verified image assets at files/ root
  release/
    image-descriptor.json
    rootfs.ext4
    rootfs.verity
    rootfs.roothash
    mvm-meta.json
    rootfs.signature.json
    provenance.json
    provenance.signature.json
```

A future protected observer transports `registry/` after the **existing**
protected `publish.yml@main` publisher has supplied its manifest bundle.
Nothing here wires that job or creates a second publisher. Local install must
require the expected exact reference and manifest SHA, and verify the bundle
normally; unsigned preparation is not an installation bypass.

The private `registry/files/` inventory is exactly the union of manifest file
paths and image descriptor asset names. Image assets are copied from the
independently verified release snapshot, bounded individually by their signed
sizes, separately from the 64 MiB source payload bound. No image descriptor
file is included in this transport inventory. Public registry output retains
its existing pack-only files inventory and public release asset URLs.

## Integration contract still missing — do not enable publication

There is no protected prepublication observer/report integration yet. The owner
must review it before any workflow signing or observer job is enabled. That
integration must bind the exact candidate manifest **and signature bundle**
hashes in its report, alongside the observed release inventory. This unsigned
preparation cannot emit a signature hash or a successful observation report.

The existing public command still independently verifies the uploaded public
release before signing, including its public release URL contract. Its optional
`--compare-candidate <candidate-directory>` checks regenerated manifest, payload
and staged release bytes against the private candidate before signing. Any
inventory or byte drift fails closed and requires re-observation.
Comparison snapshots each candidate leaf through the existing no-follow,
nonblocking copier, bounded by its regenerated expected size. Aggregate bytes
are bounded by the regenerated inventory plus at most 1 MiB for an optional
manifest bundle. Traversal is bounded to 4160 entries and depth 64, and a final
inventory/identity check rejects additions, replacements and mutation during
comparison. Candidate hashes are calculated from these private snapshots,
never by opening an unchecked candidate path with a blocking reader.

That comparison is a drift check, **not report authentication**. It permits an
already present regular `registry/manifest.sigstore.json`, but does not trust or
verify it. A newly generated signature may have different bundle bytes even
when the manifest is identical. The future integration must either preserve
the exact observed signed registry content or re-observe and bind the final
bundle hash; it must not treat `--compare-candidate` alone as permission to
publish. No report gate is silently added to the existing public workflow.

Tests use hash-based **MOCK signatures**, never live Cosign signing.
