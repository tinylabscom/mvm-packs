# The pack registry

This repository publishes the signed pack registry `mvmctl` talks to. A pack
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

Merging to `main` runs `.github/workflows/publish.yml` when publisher inputs
change. It builds manifests (SHA-256 and size per file), re-signs each
unchanged manifest under the current release identity, and verifies every
bundle before and after transferring the output to a separate publishing job.
The job commits `packs/` only after both verification passes succeed. Changed
pack contents still require a version bump in `pack.toml`.

The new release identity is:

```
https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main
```

under the GitHub OIDC issuer. The repository rename changed this identity.
The bundles currently checked into `packs/` were signed under the former
`tinylabscom/mvm-templates` workflow identity. They do not verify against the
new identity. The first publisher run after this change must re-sign and
verify all of them; until that run completes, no checked-in pack should be
described as verified under the new identity.

The current released `mvmctl` trusts the former workflow identity by default.
Newly signed packs will not install or run under its built-in trust policy
until the corresponding client trust migration is released. An operator-supplied
`$MVM_HOME/registry/publishers.toml` replaces the built-in policy wholesale.
Do not publish under the new identity before the client migration is ready.

### Migration and breaking changes

- Use `tinylabscom/mvm-packs` for source links and `MVM_PACK_REGISTRY` URLs.
  Do not rely on redirects from the former repository URL.
- Existing signature bundles remain evidence of releases by the former
  identity. The first new publisher run replaces those bundles while keeping
  each unchanged manifest and its payload intact.
- Clients that trust only the former identity reject the new bundles. Update
  the client trust policy as part of the coordinated release.
- Existing `agent/` and `runtime/` pack references have not been renamed here;
  any move to a publisher namespace requires an explicit lockfile migration.
- The unsigned template catalog remains available through `mvmctl template`.
  It is not an official signed pack catalog.

## Using a pack

```sh
mvmctl search                                # what the registry offers
mvmctl pull agent/claude@1.0.0               # verify, install, pin
mvmctl run --policy agent/claude -- make test
```

A pack composes where its reference sits in the `--policy` order; the
signature is re-verified on every load and the manifest digest is pinned in
`$MVM_HOME/registry/packs.lock.toml`.
