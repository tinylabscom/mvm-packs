# Codex policy runtime scaffold

This is not a Codex CLI installation. It contains Node 22, git, curl, ripgrep
and jq. The default command checks the Node version and exits; it does not
start an agent, contact a provider, or wait in a placeholder loop.

Before generating, configure the host's signed-pack publisher trust policy,
then run `mvmctl pull agent/codex@1.0.0`. Pull recursively verifies and installs
the signed profile's dependencies (currently `runtime/node`); their selected
versions are recorded in the host pack lock. These transitive references belong
to the existing signed pack and are not rewritten by this template.
Generation refuses missing or untrusted packs; it is not an offline standalone
policy. Run `mvmctl generate template agent-codex-runtime ./my-project`.

The local profile only extends that exact signed agent profile. Image packages
do not add runtime permissions or bypass the host policy ceiling.

Before launch, provision the declared `openai` stored secret and its provider
binding through `mvmctl secret set openai --provider openai` using the command's
secure input flow. Missing secrets/bindings fail admission. Do not put keys in
the flake, source tree, or command-line literals. Policy grants are not shell
environment interpolation; this template declares no key environment variables.
Provider authentication through the host secret-substitution path must be
tested when integrating a client.

To run an actual agent, add a version-pinned client installation to the Nix
image, replace `entrypoint.command` with its executable and arguments, and
validate its authentication flow, allowed destinations and writable workspace.
No client installation or agent session has been validated here.

The flake targets `aarch64-linux` and pins both direct input revisions. Generate
and review a `flake.lock` before building to lock transitive Nix inputs too.
Use `nix build .#packages.aarch64-linux.default --no-link` on an appropriate Linux
builder. The runtime check is a smoke command, not a guest boot test.
