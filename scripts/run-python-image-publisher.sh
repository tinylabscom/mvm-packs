#!/usr/bin/env bash
# Run only from publish.yml on main; the signer checks the workflow identity.
set -euo pipefail

[[ "$GITHUB_REF" == refs/heads/main ]] || exit 1
[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]] || exit 1
[[ "$MVMCTL_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || exit 1
[[ "$MVMCTL_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ -d "$RUNNER_TEMP" ]] || exit 1

base_dir="$RUNNER_TEMP/image-set-release"
work_dir="$RUNNER_TEMP/python-image-work"
output_dir="$RUNNER_TEMP/python-image-output"
mkdir -p "$base_dir" "$work_dir/pack-sources/runtime" \
  "$work_dir/base" "$output_dir"

# Verifies both Sigstore bundles, the signed checksum and the dispatch digest.
binary=$(bash scripts/fetch-released-mvmctl.sh)

assert_current_lock() {
  rm -f "$RUNNER_TEMP/images.lock-current"
  bash scripts/fetch-current-images-lock.sh "$RUNNER_TEMP/images.lock-current"
  cmp -s "$RUNNER_TEMP/images.lock" "$RUNNER_TEMP/images.lock-current"
}

bash scripts/fetch-current-images-lock.sh "$RUNNER_TEMP/images.lock"
set_tag=$(python3 -c 'import pathlib,tomllib; p=pathlib.Path("pack-sources/runtime/python/pack.toml"); print(tomllib.loads(p.read_text())["image_build"]["base_set"]["release_tag"])')
[[ "$set_tag" =~ ^image-set/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
gh release download "$set_tag" --repo tinylabscom/mvm-images --dir "$base_dir" \
  -p image-set.json -p image-set.json.bundle \
  -p default-microvm-vmlinux-x86_64 \
  -p default-microvm-rootfs-x86_64.ext4 \
  -p default-microvm-rootfs-x86_64.verity \
  -p default-microvm-rootfs-x86_64.roothash \
  -p default-microvm-meta-x86_64.json

cp -R scripts "$work_dir/scripts"
cp -R pack-sources/runtime/python "$work_dir/pack-sources/runtime/python"
install -m 0755 "$binary" "$work_dir/mvmctl"
sha256sum "$work_dir/mvmctl" | cut -d ' ' -f 1 > "$work_dir/mvmctl.sha256"
cp "$RUNNER_TEMP/images.lock" "$work_dir/images.lock"
cp "$base_dir/image-set.json" "$work_dir/image-set.json"
cp "$base_dir/image-set.json.bundle" "$work_dir/image-set.json.bundle"
for name in default-microvm-vmlinux-x86_64 \
  default-microvm-rootfs-x86_64.ext4 \
  default-microvm-rootfs-x86_64.verity \
  default-microvm-rootfs-x86_64.roothash; do
  cp "$base_dir/$name" "$work_dir/base/$name"
done
MVM_HOME="$RUNNER_TEMP/mvm-home" "$binary" \
  --builder firecracker __builder-shell-job \
  --script "$GITHUB_WORKSPACE/scripts/run-python-image-builder.sh" \
  --work-dir "$work_dir" --artifact-out "$output_dir"

candidate="$output_dir/python-image"
test -s "$candidate/candidate.json"
test -s "$candidate/composition/rootfs.ext4"
test -s "$candidate/composition/composition.json"
pack_source="$work_dir/pack-sources/runtime/python/pack.toml"
sidecar="${pack_source%/*}/mvm-meta.json"
python3 scripts/build-python-sidecar.py \
  --base-meta "$base_dir/default-microvm-meta-x86_64.json" \
  --base-rootfs "$base_dir/default-microvm-rootfs-x86_64.ext4" \
  --composed-rootfs "$candidate/composition/rootfs.ext4" \
  --pack-source "$pack_source" \
  --output "$sidecar"
reference=$(python3 -c 'import pathlib,tomllib; p=pathlib.Path("pack-sources/runtime/python/pack.toml"); print("runtime/python@" + tomllib.loads(p.read_text())["version"])')
[[ "$reference" =~ ^runtime/python@[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
assert_current_lock

evidence="$RUNNER_TEMP/signed-python-image"
python3 scripts/sign-composed-image.py \
  --composition "$candidate/composition" \
  --candidate-report "$candidate/candidate.json" \
  --reference "$reference" \
  --mvm-images-lock "$RUNNER_TEMP/images.lock" \
  --pack-source "$pack_source" \
  --mvm-meta "$sidecar" \
  --output "$evidence"
test -s "$evidence/image-evidence.sigstore.json"
python3 scripts/check-python-composed-runtime.py \
  --rootfs "$evidence/rootfs.ext4" \
  --mvm-meta "$evidence/mvm-meta.json"
assert_current_lock

release_stage="$RUNNER_TEMP/python-image-release-stage"
python3 scripts/stage-image-release.py \
  --evidence "$evidence" \
  --reference "$reference" \
  --pack-source "$pack_source" \
  --mvm-images-lock "$RUNNER_TEMP/images.lock" \
  --output "$release_stage"
assert_current_lock
