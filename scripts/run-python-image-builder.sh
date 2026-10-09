#!/bin/sh
# Run by mvmctl __builder-shell-job; /work is read-only and /out is the artifact disk.
set -eu

cache_root=$(mktemp -d /tmp/mvm-python-nix-cache.XXXXXX)
export XDG_CACHE_HOME="$cache_root"
python_output=$(nix --extra-experimental-features 'nix-command flakes' build \
  --no-link --print-out-paths --no-update-lock-file \
  path:/work/pack-sources/runtime/python/image#default)
test -x "$python_output/bin/python3"

exec "$python_output/bin/python3" /work/scripts/build-python-image.py \
  --pack-source /work/pack-sources/runtime/python/pack.toml \
  --mvmctl /work/mvmctl \
  --mvmctl-sha256-file /work/mvmctl.sha256 \
  --manifest /work/image-set.json \
  --bundle /work/image-set.json.bundle \
  --artifacts /work/base \
  --mvm-images-lock /work/images.lock \
  --output /out/python-image
