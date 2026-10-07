# mvm-packs

Remote template registry for [`mvmctl`](https://github.com/tinylabscom/mvm).

This repository holds richer, community-oriented microVM templates that are
fetched on demand by `mvmctl`'s template registry. A small core catalog
(`minimal`, `http`, `postgres`, `worker`, `python`) continues to ship inside
`mvmctl` itself so basic scaffolding works offline.

## Layout

```
index.json                 # registry manifest
templates/
  <name>/
    template.toml          # metadata: name, description, sizing, tags
    flake.nix              # guest definition using mvm.lib.<system>.mkGuest
```

## Adding a template

### 1. Add metadata

Create `templates/<name>/template.toml`:

```toml
name = "<name>"
description = "..."
default_vcpus = 1
default_memory_mib = 256
tags = ["..."]
# Optional: extra files to download and copy into the generated project.
files = ["app.py", "app/main.py"]
```

`files` is required for SDK-style templates that ship source files in
addition to the generated `flake.nix`.

### 2. Add a guest flake

Create `templates/<name>/flake.nix`. A template is a normal `mvm` flake that
uses `mvm.lib.<system>.mkGuest`. The scaffolded project copies this flake into
the user's directory, so keep paths relative and declare any application source
under an `./app` directory.

```nix
{
  inputs = {
    mvm.url     = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # or x86_64-linux
      pkgs   = import nixpkgs { inherit system; };

      appSrc = pkgs.stdenv.mkDerivation {
        pname = "my-app";
        version = "0";
        src = ./app;
        installPhase = "cp -r . $out";
      };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        inherit pkgs;
        name = "my-app-vm";

        packages = [ pkgs.curl appSrc ];

        services.app = {
          command = "${appSrc}/bin/start";
          env = {
            PORT = "8080";
          };
        };

        healthChecks.app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

See the upstream [mkGuest guide](https://github.com/tinylabscom/mvm/blob/main/public/src/content/docs/guides/nix-flakes.md) for the full API.

#### Without writing Nix: use the SDK

If you prefer to write an ordinary Python/TypeScript/Node function instead of a
flake, use the `mvm` SDK decorator. `mvmctl build compile` reads the file
statically (it is never executed on the host) and emits the `flake.nix` + launch
plan:

```python
# app.py
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    dependencies=mvm.python_deps(lockfile="uv.lock", tool="uv"),
    env={"BANNER": mvm.literal("hi")},
)
def greet(name: str) -> str:
    return f"hello {name}"
```

```bash
mvmctl build compile app.py --out .
```

The generated `flake.nix` is what the template carries; the user who runs
`mvmctl generate template <name> ./my-project` receives the SDK file *and* the
pre-generated flake.

### 3. Register the template

Add an entry to `index.json` with the matching `path` and an `mvm_version`
constraint such as `">=0.18.0"`:

```json
{
  "name": "<name>",
  "description": "...",
  "path": "templates/<name>",
  "mvm_version": ">=0.18.0"
}
```

### 4. Open a PR

Make sure `cargo fmt` and `cargo clippy` are clean in the consuming `mvm`
repo if you are also changing `mvmctl` code.

## Local testing

Point `mvmctl` at this directory with a `file://` URL:

```bash
export MVM_TEMPLATE_REGISTRY="file:///path/to/mvm-packs"
mvmctl template list
mvmctl template info <name>
mvmctl generate template <name> ./my-project
```
