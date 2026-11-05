# Publish a policy pack

Policy packs are reviewed here before the [publisher workflow](https://github.com/tinylabscom/mvm-packs/blob/main/.github/workflows/publish.yml)
signs a new, immutable version. A published policy grants permissions; it does
not install software or supply a runnable image.

1. Fork this repository and create a branch.
2. Run `just new-pack` to create a draft under `pack-sources/<namespace>/<name>/`.
   `mvm`, `agent` and `runtime` are reserved for first-party packs, because
   clients trust this registry's signing identity by default in those namespaces.
   It starts with no network access and no secret bindings. Edit `pack.toml`,
   `pack/group.toml` (or replace it with a `pack/profile.toml`), and
   `pack/README.md` to describe the purpose, setup, and use. Never commit secret
   values. In the README, say which credentials the documented workflow needs
   and which are optional; a policy binding alone does not make a secret
   mandatory. To update an existing pack, edit its source and bump the version
   in `pack.toml`; do not run the scaffold again.
3. Run `just check`. Open a pull request using the **Publish pack** template.
   Reviewers check the requested network access and secret-binding names and
   hosts. No pack is labelled official merely because it is submitted.
4. After approval and merge, the publisher builds and signs the manifest,
   pins it in `index.json`, and publishes the versioned files. The site then
   rebuilds the catalog and package pages from those published bytes.

For a policy source, `pack/README.md` is included in the signed payload, so
changing it after publication requires a new version. Application descriptors
use a separate source format and cannot include `pack/` payload files; this
scaffold does not publish applications or built images.
