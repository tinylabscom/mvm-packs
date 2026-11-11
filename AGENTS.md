# Agent instructions for mvm-packs

This repository is the signed pack registry for
[`mvmctl`](https://github.com/tinylabscom/mvm). Templates are no longer supported
or stored here. Every legacy published pack embeds its application binary in a
complete signed `.mvmpkg`, and a policy alone cannot be signed; new application
components instead carry an application payload archive pinned by a signed
descriptor, with no kernel, rootfs or base. The nine policy-only versions
published earlier are legacy, and four of them (`agent/claude@1.0.1`,
`agent/codex@1.0.0`, `runtime/python@1.0.0`, `runtime/node@1.0.0`) are revoked.
The first application pack is `agent/claude`: `2.0.0` is published but its embedded
revocation list expires 2026-11-08T14:35Z, so `2.0.1` (same rootfs and author key,
fresh list) supersedes it.

## Layout

- `index.json` — sole pack catalog (schema v2), generated from published
  manifests with exact-byte `manifest_sha256` pins for each version.
  Regenerate it with `python3 scripts/build-packs.py`; never edit it by hand.
- `pack-sources/<kind>/<name>/` — editable pack sources (`pack.toml` plus the
  files each pack ships).
- `packs/<kind>/<name>/<version>/` — the published, signed pack bundles
  (`manifest.json` + `manifest.sigstore.json` + `files/`). Never edit these by
  hand; regenerate them with `python3 scripts/build-packs.py`.
- `revocations.toml` — signed short-lived pack revocation feed.
- `tests/`, `scripts/` — Python validation and publisher-identity tooling.

## Validation

Run both before opening a pull request that touches packs or scripts:

```sh
python3 -m unittest discover -s tests
python3 scripts/validate-packs.py
```

Published registries land on `main` as versioned `chore(packs): publish …`
commits (the publish workflow pushes them with `[skip ci]`).

## Instruction-file provenance

This repository's agent instruction files are keyless-signed by
`.github/workflows/sign-instructions.yml` on a path-filtered push to `main`
(see the `mvm` instruction-provenance guide). The workflow is read-only and
never commits; verified `.sigstore.json` sidecars land beside the files in a
separate reviewed pull request.
