# Reviewed generated publication

The main-branch publisher signs and reads back pack bytes on `main`, then uses
the repository-scoped publishing App to propose the generated changes in a
pull request. Community intake proposes its generated index the same way,
without signing community metadata. Neither workflow may push generated
content directly to `main`. A signature or a successful workflow is not
approval to publish.

## Required repository settings

GitHub branch protection and rulesets are configured outside this repository;
merging a workflow or this document cannot turn them on. For `main`, require:

- At least one approving review by another human and code-owner review.
  `.github/CODEOWNERS` covers the signing, publishing, registry and community
  paths; requesting a reviewer is not the same as requiring their approval.
- The `validate` check from GitHub Actions. It runs on every pull request and
  merge group; the pull-request lane also checks reserved first-party
  namespaces. Do not substitute a successful branch check for the merge-group
  check.
- The active merge queue, with no Actions or App bypass. Keep direct pushes and
  force pushes disabled, including for administrators.

After an authorized administrator changes the settings, inspect the **effective**
protection and all rulesets targeting `main`, including organization rulesets.
For example, with repository administration read access:

```sh
gh api repos/tinylabscom/mvm-packs/branches/main/protection \
  --jq '{required_status_checks,required_pull_request_reviews,enforce_admins,allow_force_pushes}'
gh api repos/tinylabscom/mvm-packs/rulesets
gh api repos/tinylabscom/mvm-packs/rulesets/RULESET_ID \
  --jq '{enforcement,conditions,bypass_actors,rules}'
```

The review count must be at least one, `require_code_owner_reviews` must be
`true`, `validate` must be required, and the merge-queue rule must be active
for `main` with no bypass actor. Confirm that direct pushes are refused;
the presence of `.github/CODEOWNERS` alone is not protection.

## Rollout witnesses

1. Review and merge the workflow migration through the existing PR path.
   Confirm the production App token can create a generated pack PR while the
   main-branch signer identity and signed-byte readback are unchanged.
2. Enable and read back the protection above. For a generated pack PR, record
   the human/code-owner approval, successful `validate` on both PR and
   merge-group heads, and the merge-queue receipt before calling it published.
3. Once a real community publisher reference with independently verifiable
   signed metadata exists, witness the community workflow proposing its
   generated index in a PR. Record the same review, check and queue evidence.
   An empty scheduled intake that makes no changes is **not** this witness.

Keep any missing witness open in [issue #157](https://github.com/tinylabscom/mvm-packs/issues/157).
Do not invent a publisher, sign test metadata with an official key, or merge a
generated PR merely to satisfy the rollout checklist.
