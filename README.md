# mvm-packs

The signed pack registry for [`mvmctl`](https://github.com/tinylabscom/mvm).
This repository was formerly named `mvm-templates`; templates are no longer
its supported interface.

## Pack catalog

[`index.json`](index.json) is the main list of published packs.
[`packs/index.json`](packs/index.json) is a generated compatibility copy for
existing pack clients. Both are derived from published manifests, not from
unpublished source metadata, and validation requires them to match exactly.
Do not edit either catalog by hand.

### Initial supported pack: Claude

`agent/claude@1.0.1` is the initial supported **Claude Code policy pack**.
It provides policy for LLM APIs, GitHub, and the Anthropic secret binding.
It does not install Claude Code or provide a runnable Claude VM image.
The planned runnable environment is described in
[`CLAUDE-ENVIRONMENT.md`](CLAUDE-ENVIRONMENT.md).

```sh
mvmctl search
mvmctl pull agent/claude@1.0.1
mvmctl run --policy agent/claude -- make test
```

Other published packs remain in the catalog; publication alone is not a
claim that they are in the initial supported scope.

## Signatures and trust

Catalogs are discovery metadata, not proof of authenticity. Each published
pack has a signed `manifest.json` and an adjacent `manifest.sigstore.json`:

- [Claude manifest](packs/agent/claude/1.0.1/manifest.json)
- [Claude signature bundle](packs/agent/claude/1.0.1/manifest.sigstore.json)

The manifest binds the pack reference, description, and payload SHA-256
digests and sizes. Clients must verify its signature against the publisher
trust policy before trusting those bytes. See
[`README.packs.md`](README.packs.md#publishing) for publisher identities,
historical-signature handling, and revocation requirements.

## Layout

```text
index.json                         # main pack catalog (generated)
pack-sources/<namespace>/<name>/    # editable pack.toml and pack/ payload
packs/index.json                   # compatibility catalog (generated)
packs/<namespace>/<name>/<version>/
  manifest.json                    # signed metadata and payload digests
  manifest.sigstore.json           # detached Sigstore bundle
  files/                           # manifest-declared payload
```

## Publishing and validation

Edit a source under `pack-sources/` and bump its version when content changes.
The publisher builds and keyless-signs bundles, regenerates both catalogs,
verifies the registry, and commits the published output. Published versions
are immutable; never hand-edit their manifests, signatures, or payloads.

Run the repository checks:

```sh
python3 -m unittest discover -s tests
python3 scripts/validate-packs.py
```

To additionally verify publisher signatures (requires `cosign`):

```sh
python3 scripts/validate-packs.py --verify-signatures
```

Full publishing and revocation validation is documented in
[`README.packs.md`](README.packs.md).
