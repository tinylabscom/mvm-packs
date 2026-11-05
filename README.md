# mvm-packs

The signed pack registry for [`mvmctl`](https://github.com/tinylabscom/mvm).
This repository was formerly named `mvm-templates`; templates are no longer
its supported interface.

## Pack catalog

[`index.json`](index.json) is the main list of published packs.
It is the only catalog. Schema v2 lists each version together with the
`manifest_sha256` of its exact published `manifest.json` bytes. It is generated
from published manifests, not unpublished source metadata, and validation
requires every entry and digest to match. Do not edit it by hand.

Browse the generated [pack registry pages](docs/registry/README.md) for a
human-readable index and individual pack details. The generator reads
`index.json`, the pinned published manifests, pack policy files and
`revocations.toml`; the Markdown is rendered as a
[static site](https://tinylabscom.github.io/mvm-packs/) and deployed from
`main` by the Pages workflow.

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
index.json                         # sole pack catalog, schema v2 (generated)
pack-sources/<namespace>/<name>/    # editable pack.toml and pack/ payload
packs/<namespace>/<name>/<version>/
  manifest.json                    # signed metadata and payload digests
  manifest.sigstore.json           # detached Sigstore bundle
  files/                           # manifest-declared payload
```

## Publishing and validation

Edit a source under `pack-sources/` and bump its version when content changes.
The publisher builds and keyless-signs bundles, regenerates the root catalog,
verifies the registry, and commits the published output. Published versions
are immutable; never hand-edit their manifests, signatures, or payloads.

Run the repository checks:

```sh
python3 -m unittest discover -s tests
python3 scripts/build-pack-pages.py --check
python3 scripts/validate-packs.py
```

With [`just`](https://github.com/casey/just) installed, plain `just` lists the
available recipes; `just check` runs these checks. Use `just pages` to regenerate
`docs/registry/`, or `just pages-check` to check them without writing. To preview
the Starlight site locally, use Node.js 22.23.4 or newer (`.node-version`).
If `mise` is installed, the recipes select that version automatically:

```sh
just pages-install
just pages-dev
```

Open <http://127.0.0.1:8000/mvm-packs/>. The preview rebuilds when the catalog,
revocations or published pack files change; Ctrl+C stops the server.

To additionally verify publisher signatures (requires `cosign`):

```sh
python3 scripts/validate-packs.py --verify-signatures
```

Full publishing and revocation validation is documented in
[`README.packs.md`](README.packs.md).
