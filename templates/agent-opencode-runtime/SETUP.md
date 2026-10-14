# OpenCode policy runtime scaffold

This is not an OpenCode installation. It contains Python, Node 22, git, curl,
ripgrep and jq. The default command checks runtime versions and exits; it does
not start an agent, contact a provider, or wait in a placeholder loop.

Before generating, configure the host's signed-pack publisher trust policy,
then run `mvmctl pull agent/opencode@1.0.0`. Pull recursively verifies any signed
dependencies and records selected versions in the host pack lock; this profile
currently uses built-in groups only. Generation refuses missing or untrusted
packs. Run `mvmctl generate template agent-opencode-runtime ./my-project`.

The local profile only extends that exact signed agent profile. Python and Node
image packages do not grant PyPI or npm runtime egress; package installation
happens at build time. Host policy ceilings still apply.

Both `anthropic` and `openai` are declared secret bindings, not optional inert
entries. Before launch, provision both with `mvmctl secret set anthropic
--provider anthropic` and `mvmctl secret set openai --provider openai`, using the
commands' secure input flow. Missing secrets/bindings fail admission. Do not put
keys in source files or command-line literals. Policy grants are not shell
environment interpolation; this template declares no key environment variables.
To use only one provider, explicitly narrow the project policy and validate the
resolved profile instead of assuming an unused binding is optional.

To run an actual agent, add a version-pinned client installation to the Nix
image, replace `entrypoint.command` with its executable and arguments, and
validate host secret-substitution authentication, allowed destinations and a
writable workspace. No client installation or agent session is validated here.

The flake targets `aarch64-linux` and pins both direct input revisions. Generate
and review a `flake.lock` before building to lock transitive Nix inputs too.
Use `nix build .#packages.aarch64-linux.default --no-link` on an appropriate Linux
builder. The runtime check is a smoke command, not a guest boot test.
