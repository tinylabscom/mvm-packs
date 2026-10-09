#!/bin/sh
# Run as an mvmctl builder shell job with this checkout mounted at /work.
set -eu

cache_root=$(mktemp -d /tmp/mvm-python-nix-cache.XXXXXX)
stage_root=$(mktemp -d /tmp/mvm-python-stage.XXXXXX)
export XDG_CACHE_HOME="$cache_root"

python_output=$(nix --extra-experimental-features 'nix-command flakes' build \
    --no-link --print-out-paths --no-update-lock-file \
    path:/work/pack-sources/runtime/python/image#default)
test -x "$python_output/bin/python3"

"$python_output/bin/python3" /work/scripts/stage-python-closure.py \
    --output "$stage_root/root"
tar -C "$stage_root" -cf /out/python-tree.tar root
