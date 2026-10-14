#!/usr/bin/env bash
# Commit one newly signed image pack version and push it to main.
#
# The registry change must be exactly the new immutable version directory plus
# root index.json. The checkout is the dispatched commit, which
# can be behind main when a long image run finishes, so the commit is replayed
# onto the current main. A conflict, an index that no longer matches the tree,
# or a registry that fails signature validation refuses the push. Publication
# runs share the workflow concurrency group with the catalogue publisher, so
# no other publisher run writes packs/ while this one is in progress.
set -euo pipefail

source_dir=${1:?usage: commit-image-pack.sh PACK_SOURCE_DIR}
namespace=$(basename "$(dirname "$source_dir")")
name=$(basename "$source_dir")
version=$(python3 -c 'import pathlib,sys,tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["version"])' \
  "$source_dir/pack.toml")
[[ "$namespace/$name" =~ ^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$ ]] || exit 1
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
target="packs/$namespace/$name/$version"
test -f "$target/manifest.json"
test -f "$target/manifest.sigstore.json"

# Refuse anything but the new version and the generated root index.
unexpected=$(git status --porcelain --untracked-files=all \
  | awk '{print $NF}' \
  | grep -v -e "^${target}/" -e '^index.json$' || true)
if [[ -n "$unexpected" ]]; then
  echo "commit-image-pack: unexpected working-tree changes:" >&2
  printf '%s\n' "$unexpected" >&2
  exit 1
fi
if git ls-tree -d --name-only HEAD "$target" | grep -q .; then
  echo "commit-image-pack: $target is already committed" >&2
  exit 1
fi

git add -- "$target" index.json
git -c user.name='MVM Pack Publisher' \
  -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  commit -m "chore(packs): publish signed ${namespace}/${name}@${version} image pack [skip ci]"

git fetch --no-tags origin main
if ! git merge-base --is-ancestor origin/main HEAD; then
  git -c user.name='MVM Pack Publisher' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    rebase origin/main
  if git ls-tree -d --name-only HEAD^ "$target" | grep -q .; then
    echo "commit-image-pack: main already carries $target" >&2
    exit 1
  fi
  python3 -c 'import importlib.util,pathlib; p=pathlib.Path("scripts/build-packs.py"); s=importlib.util.spec_from_file_location("build_packs", p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.rebuild_index()'
  if ! git diff --quiet -- index.json; then
    echo "commit-image-pack: index does not match the rebased registry" >&2
    exit 1
  fi
  python3 scripts/validate-packs.py --verify-signatures --require-revocations
fi
test "$(git rev-list --count origin/main..HEAD)" = 1
git push origin HEAD:main
