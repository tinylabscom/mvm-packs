# The pack registry

This repository is also the signed pack registry `mvmctl` talks to. A pack
ships machine-readable policy — a profile (`pack/profile.toml`), a group
(`pack/group.toml`), or both — plus any payload files the manifest declares,
signed keyless by the publish workflow.

## Layout

Sources live under `pack-sources/<namespace>/<name>/`:

```
pack-sources/runtime/python/
├── pack.toml          # version = "1.1.0"; [image] selects pack/image/mvm.toml
└── pack/
    ├── group.toml     # composable policy (profile.toml also allowed)
    └── image/         # signed image manifest, flake and lock
```

An image-bearing pack can also declare `[image]` in `pack.toml`:

```toml
version = "1.1.0"
description = "Python runtime policy and image"

[image]
manifest = "pack/image/mvm.toml"
```

The payload must then include `pack/image/mvm.toml`, `pack/image/flake.nix`,
and `pack/image/flake.lock`. All three are hashed into the signed manifest.
The image manifest may contain only `schema_version`, `flake`, `profile`, and
`name`; `flake` must be `"."` (or omitted). Host grants belong to the operator's
policy, never to a publisher's image manifest. A changed source requires a new
pack version.

The workflow builds the published layout under `packs/`:

```
packs/index.json                                  # registry index (mvmctl search)
packs/<ns>/<name>/<version>/manifest.json         # RegistryPackManifest, schema v1
packs/<ns>/<name>/<version>/manifest.sigstore.json# detached cosign bundle
packs/<ns>/<name>/<version>/files/...             # payload, digest-pinned by the manifest
```

## Publishing

Merging to `main` runs `.github/workflows/publish.yml` when `pack-sources/`
changes. It builds manifests (SHA-256 and size per file), signs each manifest
keyless with `cosign sign-blob` while the run's OIDC identity is
`refs/heads/main`, validates the layout with `scripts/validate-packs.py`,
and commits `packs/`. Published versions are immutable: change a source and
the build refuses until the version in `pack.toml` is bumped.

Clients verify on every use — pull, and every policy load — against the
publisher trust policy. With no operator policy file, mvm's built-in default
accepts exactly this workflow's identity:

```
https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main
```

under the GitHub OIDC issuer. Writing `$MVM_HOME/registry/publishers.toml`
replaces that default wholesale.

## Using a pack

```sh
mvmctl search                                # what the registry offers
mvmctl pull agent/claude@1.0.1               # verify, install, pin
mvmctl run --policy agent/claude -- make test
```

A pack composes where its reference sits in the `--policy` order; the
signature is re-verified on every load and the manifest digest is pinned in
`$MVM_HOME/registry/packs.lock.toml`.

An application can also include a pack's verified policy without using its
image. For example, after pulling `runtime/python`, an application's
`mvm.toml` can compose the pack group with its own policy:

```toml
[policy]
include = ["runtime/python", "./policy/app.toml"]
```

The application group can tighten the pack's grants; denies win. A generated
template exposes its shipped policy through the same `[policy]` table.
An explicit `--policy` on `run` replaces the project table, so name every
desired layer on the command line when using that override.
