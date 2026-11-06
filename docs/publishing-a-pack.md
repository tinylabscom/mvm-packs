# Publish a pack

Every pack must embed its application binary in a `.mvmpkg`. A policy alone
cannot be signed: without the binary, a pack could run with any binary. The
[publisher workflow](https://github.com/tinylabscom/mvm-packs/blob/main/.github/workflows/publish.yml)
signs a new, immutable descriptor only after it has read back the pinned
archive and checked its digest, signature, kernel, rootfs and `[requirements]`
(see [application packs](application-packs.md)). The nine policy-only
versions published earlier are legacy and are not replaced in place; no new
policy-only version can be built or validated.

1. Fork this repository and create a branch.
2. Run `just new-pack` to create `pack-sources/<namespace>/<name>/pack.toml`.
   `mvm`, `agent` and `runtime` are reserved for first-party packs, because
   clients trust this registry's signing identity by default in those namespaces.
3. Build the `.mvmpkg` (the application, its utilities and the policy it ships
   with), host it, and fill in `[application]` with its source URL, sha256,
   size and publisher `key_id`. Add `[requirements]` for the packages,
   commands, binary pin and environment policy the archive must contain.
   Never commit secret values. The draft fails to build until the placeholders
   are replaced.
4. Run `just check`. Open a pull request using the **Publish pack** template.
   Reviewers check the pinned archive, requested network access and
   secret-binding names and hosts. No pack is labelled official merely
   because it is submitted.
5. After approval and merge, the publisher builds and signs the descriptor,
   pins it in `index.json`, and publishes the versioned files. The site then
   rebuilds the catalog and package pages from those published bytes.

An application source contains only `pack.toml`; payload files cannot sit
beside it. To update a pack, edit `pack.toml` and bump the version.
