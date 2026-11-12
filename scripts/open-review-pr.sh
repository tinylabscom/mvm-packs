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
gh pr create --base main --head "$branch" --title "$title" --body "$body"
