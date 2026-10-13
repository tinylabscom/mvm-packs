#!/usr/bin/env bash
# Write mvm's images.lock, read at a freshly resolved main commit, to $1.
# Publication jobs fetch it independently instead of trusting a copy from an
# earlier job: staging rejects evidence whose provenance names another lock,
# so a base-set move between jobs refuses publication.
set -euo pipefail

destination=${1:?usage: fetch-current-images-lock.sh DESTINATION}
if [[ -e "$destination" || -L "$destination" ]]; then
  echo "fetch-current-images-lock: refusing to replace $destination" >&2
  exit 1
fi
sha=$(gh api repos/tinylabscom/mvm/commits/main --jq .sha)
[[ "$sha" =~ ^[0-9a-f]{40}$ ]]
gh api -H 'Accept: application/vnd.github.raw+json' \
  "repos/tinylabscom/mvm/contents/crates/mvm-core/images.lock?ref=$sha" \
  > "$destination"
test -s "$destination"
