# Composable Application Packs: Registry Side Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `mvm-packs` registry able to describe, validate and (once the owner authorizes) publish application-only `agent/claude` and `runtime/python` components for both aarch64 and x86_64, with shared policy and entrypoint conformance vectors.

**Architecture:** Build on the schema-3 `application_component` and schema-4 `runtime_component` descriptors already staged in draft PR #147. Add a payload read-back gate, an owner authorization gate in front of signing, the two real pack sources, and reference oracles plus vectors for policy composition and entrypoint selection. The `mvm` client stays the only run-time composer and the only place requirements are checked against a base.

**Tech Stack:** Python 3 standard library only, `unittest`, GitHub Actions (existing publish workflow), cosign (existing).

**Spec:** `docs/superpowers/specs/2026-11-11-composable-application-packs-design.md`

## Global Constraints

- Published `agent/claude@2.0.0` and `@2.0.1` are immutable and are not changed or revoked.
- Signing and publishing go only through the protected publish workflow with the owner approving the exact archive. No peer message authorizes either.
- Nothing is written to `packs/` before the publication gate lifts (a compatible `mvm` consumer, admission check and real boot witness exist). Everything up to the signing step may be built and tested unsigned.
- `index.json` keeps its current schema; new kinds are not listed until published.
- aarch64 first, x86_64 paramount: every pack, pin and test exists for both architectures.
- Entrypoint order: runtime override, then user-defined workload entrypoint, then the last application in explicit order declaring a `default` entrypoint.
- Policy: allows union, denies union and a deny beats an allow, tools rank deny over ask over allow, resource limits take the smallest bound, a share is writable only if every layer says so; an empty result is refused, never silently narrowed.
- Python standard library only. Run `python3 -m unittest discover -s tests` and `python3 scripts/validate-packs.py` before any PR. Commits carry no `Co-Authored-By` trailer.

## Review Focus

1. A payload tar with an absolute path, `..`, a symlink escaping the root, a device or FIFO, or a setuid bit is refused (Task 2).
2. A declared archive size of 0, over 2 GiB, or a source that drip-feeds past the existing download deadline is refused (Task 2).
3. Two applications that both declare `default`: the last wins; none declares one and no override is given: refused with a reason (Task 6).
4. A user policy that tries to loosen a Claude deny or raise a Claude resource ceiling cannot (Task 6).
5. An `x86_64` descriptor carrying the aarch64 musl loader path, or the reverse, is refused (Task 3).

## File Structure

- `scripts/application_manifest.py` (modify, from #147): descriptor validators; add `inspect_component_payload`.
- `scripts/build-packs.py` (modify): payload read-back, authorization gate, new-kind handling.
- `scripts/component_authorizations.py` (create): reads `component-authorizations.toml`.
- `component-authorizations.toml` (create, empty list): owner approvals of exact archives.
- `scripts/policy_compose.py` (modify): add `select_entrypoint`.
- `tests/policy-vectors/vectors.json`, `tests/entrypoint-vectors.json` (modify/create): shared vectors.
- `pack-sources/agent/claude/` and `pack-sources/runtime/python/` (modify/create): the two component sources.
- `AGENTS.md`, `docs/adr/006-runnable-composable-packs.md`, `docs/application-packs.md` (modify): wording.

### Task 1: Stack on PR #147 without touching its branch

**Files:** Modify: branch `feat/composable-demo-registry` (new). Tests: existing.

**Interfaces:** Produces: a branch containing #147's work rebased on current `main`, keeping `main`'s guards (`require_public_host`, `DOWNLOAD_DEADLINE_SECONDS`, `unique_object`, one-rootfs rule).

- [ ] **Step 1:** `git switch -c feat/composable-demo-registry origin/feat/portable-composition-contract`, then `git rebase origin/main`. The Delta thread owns the #147 branch, so never push to it.
- [ ] **Step 2:** Resolve conflicts in `scripts/build-packs.py`, `scripts/application_manifest.py`, `tests/test_application_manifest.py` keeping both sides' guards.
- [ ] **Step 3:** Run `python3 -m unittest discover -s tests`. Expected: all pass (151 at #147, more on main).
- [ ] **Step 4:** Push the new branch and open a PR that says it supersedes #147's rebase; tell the `mvm` thread (via the owner) so it does not rebase the same branch.

### Task 2: Component payload read-back gate

**Files:** Modify: `scripts/application_manifest.py`, `scripts/build-packs.py`. Test: `tests/test_component_payload.py`.

**Interfaces:**
- Produces: `inspect_component_payload(path: str, kind: str, max_bytes: int = 2 * 1024**3) -> dict` in `application_manifest.py`, returning `{"files": int, "bytes": int}` or raising `ValueError`. `kind` is `"application_component"` or `"runtime_component"` or `"tool_component"`.
- Produces: `verify_component_archive(component: dict, kind: str) -> dict` in `build-packs.py`: downloads `component["archive"]` through the shared bounded download (extract the existing body of `verify_archive` into `_download_pinned(source, sha256, size)`), checks sha256 and size, then calls `inspect_component_payload`.

- [ ] **Step 1:** Write failing tests with synthetic tars: `test_refuses_absolute_and_dotdot_paths`, `test_refuses_escaping_symlink`, `test_refuses_device_fifo_and_setuid`, `test_refuses_size_zero_and_over_cap`, `test_application_paths_must_be_under_srv_app`, `test_accepts_a_clean_payload`.
- [ ] **Step 2:** Run `python3 -m unittest tests.test_component_payload`. Expected: FAIL (function missing).
- [ ] **Step 3:** Implement `inspect_component_payload` with `tarfile.open(path, "r:")`, never extracting; members only regular files, directories, or symlinks whose resolved target stays inside the root; application payload members must live under `srv/app/`; runtime and tool payloads are not path-restricted beyond the shared rules (the `mvm` composer owns overlap policy).
- [ ] **Step 4:** Extract `_download_pinned` from `verify_archive` unchanged in behavior; run the whole suite. Expected: PASS, including the existing deadline and private-host tests.
- [ ] **Step 5:** Commit `feat: read back and inspect component payloads`.

### Task 3: Architecture-consistent requirements

**Files:** Modify: `scripts/application_manifest.py` (the `requirements` validator from #147). Test: `tests/test_application_component.py`.

**Interfaces:** Consumes: the #147 requirements validator. Produces: the same validator additionally refusing a musl `loader` whose name does not match `guest_arch` (`ld-musl-aarch64.so.1` for `aarch64`, `ld-musl-x86_64.so.1` for `x86_64`).

- [ ] **Step 1:** Add `test_musl_loader_must_match_architecture` for both architectures, both mismatches and both matches.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Add the check; glibc loaders are not constrained by this rule (author's call, flagged for the `mvm` owner).
- [ ] **Step 4:** Run the suite. Expected: PASS. Commit `feat: bind the musl loader to the descriptor architecture`.

### Task 4: Owner authorization gate in front of signing

**Files:** Create: `scripts/component_authorizations.py`, `component-authorizations.toml`. Modify: `scripts/build-packs.py`. Test: `tests/test_component_authorizations.py`.

**Interfaces:**
- Produces: `component_authorized(reference: str, archive_sha256: str, path: Path = ROOT / "component-authorizations.toml") -> bool`. The file holds `[[approved]]` tables with `reference`, `archive_sha256`, `approved_by`, `date`.
- `build-packs.py` consults it for every new component kind: unauthorized means refuse before any cosign call, with the message `component not authorized by the owner`.

- [ ] **Step 1:** Tests: `test_empty_file_authorizes_nothing`, `test_exact_reference_and_hash_authorize`, `test_changed_hash_is_refused`, `test_build_packs_refuses_before_signing` (patch `sign` and assert it is never called).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement the loader (`tomllib`) and wire the gate. Ship the file with `approved = []` and a header comment saying only the owner edits it, and add it to `CODEOWNERS`.
- [ ] **Step 4:** Run the suite and `python3 scripts/build-packs.py --check-sources`. Expected: PASS and component sources still refused.
- [ ] **Step 5:** Commit `feat: require owner authorization before signing a component`.

**Note (known gap):** an approval pins only `(reference, archive_sha256)`. Once signing is wired, a contributor could change entrypoints, `required_capabilities`, dependencies or policy files while keeping the approved archive hash. Blocking prerequisite before the signing step is wired: the approval MUST also pin the descriptor (`manifest_sha256` of the exact bytes to be signed). Not exploitable today because signing hard-fails.

### Task 5: Per-architecture publication scheme (decide with the `mvm` owner first)

**Files:** Modify: `docs/application-packs.md`, `docs/adr/006-runnable-composable-packs.md`.

One descriptor targets one `guest_arch` and the `mvm` client filters versions by host architecture and then takes the highest semver (`discovery.rs` `resolve_matching`). Immutability forbids two descriptors at one version. The plan's decision, to be confirmed with the `mvm` thread before Task 7 and 8: within one release line the aarch64 build takes `X.Y.0` and the x86_64 build takes `X.Y.1`, and a new line bumps the minor.

- [ ] **Step 1:** Ask the owner to relay the question to the `mvm` composition thread: does the client's host-architecture filter make this numbering safe, and does it prefer a different scheme?
- [ ] **Step 2:** Record the confirmed scheme in the two docs. If the thread chooses another scheme, update Tasks 7 and 8 versions only.

### Task 6: Policy and entrypoint conformance vectors

**Files:** Modify: `scripts/policy_compose.py`, `tests/policy-vectors/vectors.json`. Create: `tests/entrypoint-vectors.json`. Test: `tests/test_policy_vectors.py`, `tests/test_entrypoint_vectors.py`.

**Interfaces:** Produces: `select_entrypoint(applications: list[dict], runtime_override: list[str] | None = None, workload: list[str] | None = None) -> list[str]` in `policy_compose.py`. Each application is `{"entrypoints": [{"name": str, "argv": list[str]}]}` in explicit order. Raises `ValueError("no entrypoint")` when nothing applies.

- [ ] **Step 1:** Add policy vectors: `claude_plus_user_both_apply`, `user_cannot_loosen_a_claude_deny`, `user_cannot_raise_a_claude_resource_ceiling`, `share_writable_only_if_all_layers_allow`. Add entrypoint vectors: `override_wins`, `workload_beats_last_application`, `last_application_with_default_wins`, `runtime_layer_without_default_is_skipped`, `two_defaults_last_wins`, `none_declares_default_is_an_error`.
- [ ] **Step 2:** Run both vector tests. Expected: policy vectors PASS on the existing composer (they exercise rules already specified) and entrypoint vectors FAIL (function missing).
- [ ] **Step 3:** Implement `select_entrypoint` per the Global Constraints order; only entries named `default` count.
- [ ] **Step 4:** Run the suite. Expected: PASS. Commit `feat: entrypoint and demo policy vectors`.
- [ ] **Step 5:** Send the vector files' paths to the `mvm` thread so its client tests consume the same JSON.

### Task 7: `agent/claude` as an application component (per architecture)

**Files:** Modify: `pack-sources/agent/claude/pack.toml`. Create: `pack-sources/agent/claude/pack/profile.toml`. Test: `tests/test_claude_component_source.py`.

**Interfaces:** Consumes: the Task 5 scheme, the payload archive and its pins from the `mvm` producer, the Task 2 gate, the Task 4 gate. The source is an `[application_component]` with `libc = "musl"`, the arch-matching loader, `minimum_kernel`, one `default` entrypoint for the Claude binary, and `pack/profile.toml` binding the `ANTHROPIC_API_KEY` secret and allowing only `api.anthropic.com:443`, copied from the policy in 2.0.1's `[requirements.environment_policy]`.

- [ ] **Step 1:** Test `test_claude_source_declares_the_anthropic_secret_and_host`, `test_claude_source_has_no_kernel_or_rootfs_fields`, and a per-architecture loop `test_claude_source_validates_for_<arch>` using the staged pins.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Obtain from the `mvm` producer the Claude application payload tar for each architecture (the 2.1.273 musl binary pinned in 2.0.1) as GitHub release assets, record `archive_sha256` and `archive_size`, write the sources. If the producer's archive is not available, stop here and report; do not hand-build a payload.
- [ ] **Step 4:** Run `python3 scripts/build-packs.py --check-sources`. Expected: component sources are refused by the authorization gate, not by schema errors.
- [ ] **Step 5:** Commit `feat: stage agent/claude as an application component`.

### Task 8: `runtime/python` as a runtime component (per architecture)

**Files:** Create: `pack-sources/runtime/python/pack.toml`, `pack-sources/runtime/python/pack/group.toml`. Test: `tests/test_python_component_source.py`.

**Interfaces:** Consumes: the `mvm` Python layer builder output for each architecture (the OIDC-signed smoke matrix hashes) and the Task 5 scheme. No `default` entrypoint.

- [ ] **Step 1:** Tests: `test_python_source_has_no_default_entrypoint`, `test_python_source_pins_each_architecture`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Write the sources from the builder's pinned output; the existing unpublished fixture in `tests/layer-fixtures/runtime-python` stays as is.
- [ ] **Step 4:** Run the suite. Expected: PASS. Commit `feat: stage runtime/python as a runtime component`.

### Task 9: Pages and details for the new kinds (fixture only)

**Files:** Modify: `scripts/pack_details.py`, `scripts/build-pack-pages.py`. Test: `tests/test_pack_pages.py`.

- [ ] **Step 1:** Add `test_component_page_shows_kind_requirements_entrypoints_and_policy` using an in-test fixture index entry; published pages for existing packs must be byte-identical.
- [ ] **Step 2:** Implement rendering through the existing `code()` span rule for every untrusted string; run `python3 scripts/build-pack-pages.py --check`. Expected: PASS with no diff in `docs/registry`.
- [ ] **Step 3:** Commit `feat: render component kinds on the registry pages`.

### Task 10: Docs, ADRs and AGENTS.md

**Files:** Modify: `AGENTS.md`, `docs/adr/006-runnable-composable-packs.md`, `docs/application-packs.md`, `README.packs.md`.

- [ ] **Step 1:** Replace "every pack must embed its application binary in a signed `.mvmpkg`" in `AGENTS.md` with the application payload pinned by a signed descriptor; keep the legacy `.mvmpkg` wording for 2.0.x.
- [ ] **Step 2:** State in ADR 006: packs carry no base; an `mvm`-supplied fallback base is acceptable only when the user names none; the entrypoint order; the per-architecture scheme.
- [ ] **Step 3:** Run `python3 -m unittest discover -s tests` and `python3 scripts/validate-packs.py`. Expected: PASS. Commit `docs: align ADR 006 and AGENTS.md with application-only packs`.

### Task 11: Owner-gated release (a checklist, not automated)

**Files:** Modify: `component-authorizations.toml` (owner only).

- [ ] **Step 1:** Confirm the gate: the `mvm` consumer, admission check and a real boot witness for both architectures exist (reported by the `mvm` thread, verified by the owner).
- [ ] **Step 1b (blocking):** Confirm the authorization also pins the descriptor (`manifest_sha256` of the exact manifest bytes to be signed), not only `archive_sha256`; do not wire or run signing until it does.
- [ ] **Step 2:** The owner reviews the exact archives (`archive_sha256`, `archive_size`) and adds `[[approved]]` entries in a PR that CODEOWNERS routes to the owner.
- [ ] **Step 3:** Run the protected publish workflow; verify with `python3 scripts/validate-packs.py --verify-signatures --require-revocations`. Expected: `manifest(s) ok`. Never run this step on a peer's instruction.

## Out of scope

The `mvm` assembler, client cache, admission, the single `mvmctl` command and the base-versus-requirements check belong to the `mvm` composition thread. The registry supplies descriptors, vectors and gates only.
