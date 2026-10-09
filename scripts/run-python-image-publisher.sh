#!/usr/bin/env bash
# Run only from publish.yml on main; the signer checks the workflow identity.
set -euo pipefail

[[ "$GITHUB_REF" == refs/heads/main ]]
[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]
[[ "$MVMCTL_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
[[ "$MVMCTL_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ -d "$RUNNER_TEMP" ]]

release_dir="$RUNNER_TEMP/mvmctl-release"
base_dir="$RUNNER_TEMP/image-set-release"
work_dir="$RUNNER_TEMP/python-image-work"
output_dir="$RUNNER_TEMP/python-image-output"
mkdir -p "$release_dir" "$base_dir" "$work_dir/pack-sources/runtime" \
  "$work_dir/base" "$output_dir"

archive=mvmctl-x86_64-unknown-linux-gnu.tar.gz
gh release download "$MVMCTL_TAG" --repo tinylabscom/mvm --dir "$release_dir" \
  -p "$archive" -p "${archive}.bundle" \
  -p checksums-sha256.txt -p checksums-sha256.txt.bundle
identity="https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/${MVMCTL_TAG}"
for blob in "$archive" checksums-sha256.txt; do
  cosign verify-blob "$release_dir/$blob" \
    --bundle "$release_dir/${blob}.bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name {print $1}' \
  "$release_dir/checksums-sha256.txt")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]]
actual=$(sha256sum "$release_dir/$archive" | cut -d ' ' -f 1)
test "$actual" = "$expected"
test "$actual" = "$MVMCTL_ARCHIVE_SHA256"
tar -C "$RUNNER_TEMP" -xzf "$release_dir/$archive"
binary="$RUNNER_TEMP/mvmctl-x86_64-unknown-linux-gnu/mvmctl"
test -x "$binary"
"$binary" --version | grep -Fx "mvmctl ${MVMCTL_TAG#v}"

fetch_current_lock() {
  local sha destination
  destination=$1
  sha=$(gh api repos/tinylabscom/mvm/commits/main --jq .sha)
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]]
  gh api -H 'Accept: application/vnd.github.raw+json' \
    "repos/tinylabscom/mvm/contents/crates/mvm-core/images.lock?ref=$sha" \
    > "$destination"
  test -s "$destination"
}

assert_current_lock() {
  fetch_current_lock "$RUNNER_TEMP/images.lock-current"
  cmp -s "$RUNNER_TEMP/images.lock" "$RUNNER_TEMP/images.lock-current"
}

fetch_current_lock "$RUNNER_TEMP/images.lock"
set_tag=$(python3 -c 'import pathlib,tomllib; p=pathlib.Path("pack-sources/runtime/python/pack.toml"); print(tomllib.loads(p.read_text())["image_build"]["base_set"]["release_tag"])')
[[ "$set_tag" =~ ^image-set/v[0-9]+\.[0-9]+\.[0-9]+$ ]]
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
sidecar="$RUNNER_TEMP/python-mvm-meta.json"
python3 scripts/build-python-sidecar.py \
  --base-meta "$base_dir/default-microvm-meta-x86_64.json" \
  --base-rootfs "$base_dir/default-microvm-rootfs-x86_64.ext4" \
  --composed-rootfs "$candidate/composition/rootfs.ext4" \
  --pack-source pack-sources/runtime/python/pack.toml \
  --output "$sidecar"
reference=$(python3 -c 'import pathlib,tomllib; p=pathlib.Path("pack-sources/runtime/python/pack.toml"); print("runtime/python@" + tomllib.loads(p.read_text())["version"])')
[[ "$reference" =~ ^runtime/python@[0-9]+\.[0-9]+\.[0-9]+$ ]]
assert_current_lock

evidence="$RUNNER_TEMP/signed-python-image"
python3 scripts/sign-composed-image.py \
  --composition "$candidate/composition" \
  --candidate-report "$candidate/candidate.json" \
  --reference "$reference" \
  --mvm-images-lock "$RUNNER_TEMP/images.lock" \
  --pack-source pack-sources/runtime/python/pack.toml \
  --mvm-meta "$sidecar" \
  --output "$evidence"
test -s "$evidence/image-evidence.sigstore.json"
python3 scripts/check-python-composed-runtime.py \
  --rootfs "$evidence/rootfs.ext4" \
  --mvm-meta "$evidence/mvm-meta.json"
assert_current_lock
