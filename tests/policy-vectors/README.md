# Policy composition vectors

`vectors.json` is a list of `{name, layers, expect | error}`. `layers` are policy
fragments in order; `expect` is the resolved policy, `error` a substring of the
refusal key. `scripts/policy_compose.py` is the reference; the `mvm` client
merge (`policy_profiles/merge.rs`) must produce the same results. Ported from
its unit tests; add a vector with every rule you add to either side.
Not yet covered: network canonicalisation/block, secret-host narrowing,
env.readmit, pack-added shares.
Egress host allowlists (including the Claude pack's single allowed host) are not asserted
here: the reference composer has no network section yet, the same gap as secret-host
narrowing above.

## Entrypoint vectors

`../entrypoint-vectors.json` is a list of `{name, applications, runtime_override?,
workload?, expect | error}`. `applications` is the explicit-order list of
`{"entrypoints": [{"name", "argv"}]}`; `expect` is the chosen argv. Order: runtime
override, then workload, then the `default` entrypoint of the last application that
has one (other names are explicit-only). `scripts/policy_compose.py`
(`select_entrypoint`) is the reference; the `mvm` client must produce the same results.
