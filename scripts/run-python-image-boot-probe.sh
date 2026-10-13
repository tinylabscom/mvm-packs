#!/usr/bin/env bash
# Boot the signed runtime/python image with the released mvmctl before any
# release exists. Run only from publish.yml's boot_python_image job.
#
# Nothing from the signing job is trusted as-is: the client is downloaded and
# authenticated again, the base lock is fetched again, and the downloaded
# evidence is re-staged, which rehashes every asset and verifies every
# signature under the publisher identity before a byte of it is booted.
set -euo pipefail

[[ "$GITHUB_REF" == refs/heads/main ]] || exit 1
[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]] || exit 1
[[ "$MVMCTL_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || exit 1
[[ "$MVMCTL_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ -d "$RUNNER_TEMP" ]] || exit 1
evidence=${1:?usage: run-python-image-boot-probe.sh EVIDENCE_DIR PROBE_OUTPUT_DIR}
probe_dir=${2:?usage: run-python-image-boot-probe.sh EVIDENCE_DIR PROBE_OUTPUT_DIR}
[[ -d "$evidence" && ! -L "$evidence" ]] || exit 1
mkdir "$probe_dir"

binary=$(bash scripts/fetch-released-mvmctl.sh)

pack_source=pack-sources/runtime/python/pack.toml
reference=$(python3 -c 'import pathlib,tomllib; p=pathlib.Path("pack-sources/runtime/python/pack.toml"); print("runtime/python@" + tomllib.loads(p.read_text())["version"])')
[[ "$reference" =~ ^runtime/python@[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1

lock="$RUNNER_TEMP/images.lock"
bash scripts/fetch-current-images-lock.sh "$lock"
staged="$RUNNER_TEMP/python-image-release-stage"
python3 scripts/stage-image-release.py \
  --evidence "$evidence" \
  --reference "$reference" \
  --pack-source "$pack_source" \
  --mvm-images-lock "$lock" \
  --output "$staged"

deployment="$RUNNER_TEMP/python-image-deployment"
mkdir -m 0700 "$deployment"
for name in rootfs.ext4 rootfs.verity rootfs.roothash mvm-meta.json; do
  install -m 0400 "$staged/$name" "$deployment/$name"
done
rootfs_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"]["rootfs"]["sha256"])' \
  "$staged/image-descriptor.json")
rootfs_blake3=$(b3sum --no-names "$deployment/rootfs.ext4")
python3 scripts/write-deployment-record.py \
  --deployment "$deployment" \
  --blake3 "$rootfs_blake3" \
  --sha256 "$rootfs_sha256" \
  --workload-id runtime-python

# The released client boots the deployment on the workload kernel it
# bootstraps from its own pinned image set, with the guest runtime its own
# release ships. A missing release guest runtime fails here.
export MVM_HOME="$RUNNER_TEMP/mvm-home"
"$binary" bootstrap

command=(/bin/python3 --version)
set +e
timeout --kill-after=30 600 "$binary" run --deployment "$deployment" --timeout 120 \
  -- "${command[@]}" > "$probe_dir/stdout" 2> "$probe_dir/stderr"
status=$?
set -e

python3 scripts/check-python-boot-probe.py \
  --reference "$reference" \
  --mvmctl "$binary" \
  --mvmctl-tag "$MVMCTL_TAG" \
  --descriptor "$staged/image-descriptor.json" \
  --deployment "$deployment" \
  --command "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${command[@]}")" \
  --exit-code "$status" \
  --stdout "$probe_dir/stdout" \
  --stderr "$probe_dir/stderr" \
  --report "$probe_dir/boot-probe.json"
