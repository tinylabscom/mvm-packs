#!/usr/bin/env bash
# Download and authenticate the released Linux x86_64 mvmctl named by the
# dispatch, then unpack it under $RUNNER_TEMP. Every publication job that runs
# the client calls this rather than trusting a binary another job produced.
#
# Requires MVMCTL_TAG, MVMCTL_ARCHIVE_SHA256, RUNNER_TEMP, GH_TOKEN and a
# cosign v3 on PATH. Prints the verified executable's path on stdout.
set -euo pipefail

[[ "$MVMCTL_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || exit 1
[[ "$MVMCTL_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ -d "$RUNNER_TEMP" ]] || exit 1

release_dir="$RUNNER_TEMP/mvmctl-release"
unpack_dir="$RUNNER_TEMP/mvmctl-unpacked"
if [[ -e "$release_dir" || -e "$unpack_dir" ]]; then
  echo "fetch-released-mvmctl: refusing to reuse an existing download" >&2
  exit 1
fi
mkdir -p "$release_dir" "$unpack_dir"

archive=mvmctl-x86_64-unknown-linux-gnu.tar.gz
gh release download "$MVMCTL_TAG" --repo tinylabscom/mvm --dir "$release_dir" \
  -p "$archive" -p "${archive}.bundle" \
  -p checksums-sha256.txt -p checksums-sha256.txt.bundle >&2
identity="https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/${MVMCTL_TAG}"
for blob in "$archive" checksums-sha256.txt; do
  cosign verify-blob "$release_dir/$blob" \
    --bundle "$release_dir/${blob}.bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >&2
done
expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name {print $1}' \
  "$release_dir/checksums-sha256.txt")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || exit 1
actual=$(sha256sum "$release_dir/$archive" | cut -d ' ' -f 1)
test "$actual" = "$expected"
test "$actual" = "$MVMCTL_ARCHIVE_SHA256"
tar -C "$unpack_dir" -xzf "$release_dir/$archive"
binary="$unpack_dir/mvmctl-x86_64-unknown-linux-gnu/mvmctl"
test -f "$binary" && test ! -L "$binary" && test -x "$binary"
"$binary" --version | grep -Fx "mvmctl ${MVMCTL_TAG#v}" >&2
printf '%s\n' "$binary"
