# Agent instructions for mvm-templates

This repository is the remote template and pack registry for
[`mvmctl`](https://github.com/tinylabscom/mvm). `mvmctl` fetches templates and
packs from here on demand; a small core catalog ships inside `mvmctl` itself.

## Layout

- `index.json` — registry manifest.
- `templates/<name>/` — one `template.toml` (metadata) and one `flake.nix`
  (guest definition using `mvm.lib.<system>.mkGuest`) per template. Keep
  flake paths relative; application source lives under `./app`.
- `pack-sources/<kind>/<name>/` — editable pack sources (`pack.toml` plus the
  files each pack ships).
- `packs/<kind>/<name>/<version>/` — the published, signed pack bundles
  (`manifest.json` + `manifest.sigstore.json` + `files/`). Never edit these by
  hand; regenerate them with `python3 scripts/build-packs.py`.
- `revocations.toml` — signed short-lived pack revocation feed.
- `tests/`, `scripts/` — Python validation and publisher-identity tooling.

## Validation

Run both before opening a pull request that touches packs, templates, or
scripts:

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
