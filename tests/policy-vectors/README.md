# Policy composition vectors

`vectors.json` is a list of `{name, layers, expect | error}`. `layers` are policy
fragments in order; `expect` is the resolved policy, `error` a substring of the
refusal key. `scripts/policy_compose.py` is the reference; the `mvm` client
merge (`policy_profiles/merge.rs`) must produce the same results. Ported from
its unit tests; add a vector with every rule you add to either side.
Not yet covered: network canonicalisation/block, secret-host narrowing,
env.readmit, pack-added shares.
