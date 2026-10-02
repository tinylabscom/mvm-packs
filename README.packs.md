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
mvmctl pull agent/claude@1.0.0               # verify, install, pin
mvmctl run --policy agent/claude -- make test
```

A pack composes where its reference sits in the `--policy` order; the
signature is re-verified on every load and the manifest digest is pinned in
`$MVM_HOME/packs.lock.toml`.
