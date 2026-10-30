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

### Runnable Claude application source

`pack-sources/agent/claude` defines `agent/claude@2.0.0` as an application,
not a policy-only pack. Its descriptor pins the complete `claude.mvmpkg`
archive, which contains the native Claude binary, baked entrypoint, resources,
host-held Anthropic secret slot and one embedded allow policy for
`api.anthropic.com:443`.

The intended consumer demo, after genuine archive and registry publication, is:

```sh
mvmctl search agent/claude
mvmctl pull agent/claude
printf '%s\n' 'tell me a joke' | mvmctl run agent/claude
```

A compatible CLI, reviewed host runtime/native caller setup, trusted publishers
and one unambiguous stored Anthropic credential are one-time prerequisites.
The run must not need an extra allow-host flag, policy file, source checkout,
flake or workload IR.

This is a release source definition, not a claim that version 2.0.0 has already
been published. `index.json` remains authoritative for actual availability.
Publish the exact verified archive at its declared source before allowing the
normal registry publisher to sign and advertise its descriptor.

### Historical Claude policy pack

`agent/claude@1.0.1` is the initial supported **Claude Code policy pack**.
It provides policy for LLM APIs, GitHub, and the Anthropic secret binding.
It does not install Claude Code or provide a runnable Claude VM image.
The planned runnable environment is described in
[`CLAUDE-ENVIRONMENT.md`](CLAUDE-ENVIRONMENT.md).

```sh
mvmctl search
mvmctl pull agent/claude@1.0.1
mvmctl run --policy agent/claude@1.0.1 -- make test
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
python3 scripts/validate-packs.py
```

To additionally verify publisher signatures (requires `cosign`):

```sh
python3 scripts/validate-packs.py --verify-signatures
```

Full publishing and revocation validation is documented in
[`README.packs.md`](README.packs.md).
