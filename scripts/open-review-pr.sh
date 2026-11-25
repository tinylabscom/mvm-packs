#!/usr/bin/env bash
set -euo pipefail

kind="${1:?publication kind required}"
title="${2:?pull request title required}"
body="${3:?pull request body required}"

case "$kind" in
  packs|community) ;;
  *) echo "unknown publication kind: $kind" >&2; exit 2 ;;
esac
if [[ "${GITHUB_REF:-}" != refs/heads/main ||
      ! "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ||
      ! "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ||
      -z "${GH_TOKEN:-}" ]]; then
  echo "reviewed publication requires a main-branch workflow run and pull-request token" >&2
  exit 2
fi

if git diff --cached --quiet; then
  echo "no published changes to propose"
  exit 0
fi

branch="automation/${kind}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
git switch -c "$branch"
git -c user.name='MVM Pack Publisher' \
  -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  commit -m "chore(${kind}): propose verified publication"
git push origin "HEAD:refs/heads/$branch"
url="$(gh pr create --base main --head "$branch" --title "$title" --body "$body")"
echo "$url"

# Close earlier review PRs of this kind so only the newest stays open. The new
# PR exists by now, so a failure here warns and never fails the run.
new="${url##*/}"
if [[ ! "$new" =~ ^[0-9]+$ ]]; then
  echo "warning: cannot read the new pull request number; leaving older review PRs open" >&2
  exit 0
fi
if ! older="$(gh pr list --state open --limit 200 \
    --json number,headRefName,isCrossRepository \
    --jq ".[] | select(.isCrossRepository | not)
          | select(.headRefName | test(\"^automation/${kind}-[0-9]+-[0-9]+\$\"))
          | select(.headRefName != \"$branch\") | .number")"; then
  echo "warning: cannot list older review PRs" >&2
  exit 0
fi
for old in $older; do
  [[ "$old" == "$new" ]] && continue
  gh pr close "$old" --delete-branch \
    --comment "Superseded by #${new}: a newer signed publication was proposed by run ${GITHUB_RUN_ID}." ||
    echo "warning: could not close superseded pull request #${old}" >&2
done
