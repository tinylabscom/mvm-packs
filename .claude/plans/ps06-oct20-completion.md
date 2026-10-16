# PS-06 completion and October 20 demo plan

## Target and scope

Demo: **Tuesday, October 20, 2026, 09:00 America/Los_Angeles**
(PDT, UTC-07:00).

Deliver two distinct outcomes:

1. **Public PS-06 acceptance:** use the existing
   `runtime/python@1.1.0` Linux x86_64 image-build intent to prove the
   production build, observation, publication and fresh-recipient chain.
2. **Demo goal:** use a pinned `anthropic/claude` application pack to show
   prebuilt software delivery, automatic pack-policy loading, a real Claude
   prompt/model response, and refusal when local policy conflicts with required
   capabilities.

Python acceptance does not prove the Claude demo. A private Claude demonstration
does not satisfy public Built/image acceptance. A pack name is not publisher
authority or an assertion of Anthropic endorsement.

The demo is **standalone and transient/headless**, with pack and personal policy.
`mvm` itself owns policy composition and enforcement; it does not require
`mvmd`. The optional `mvmd` integration is post-demo work, not a prerequisite
or a deferred standalone policy engine.

This is a gated delivery plan, not permission to sign, dispatch, upload, publish,
tag, transfer private artifacts, use credentials or incur cloud/model charges.
The approved architecture is inherited; no trust bypass or second publisher is
proposed.

## Ownership

| Owner | Sole responsibility |
| --- | --- |
| Observer/acceptance owner | Protected observer, protected policy, adapter review, pack acceptance and the evidence ledger |
| Runtime/artifact owner | Lifecycle/custody APIs, prebuilt pull/run integration, artifact production, runtime/release prerequisites, canonical publisher recovery and live execution |
| User | Scope decisions and explicit authorization of concrete live/public/billable/credential operations |

Use the two existing owners. Do not create replacement sessions, competing
runtime emitters, bundlers, signers or publishers. File-level ownership must be
explicit before either owner edits the other's integration seam.

## Verified starting point: October 15

- Observer diagnostics: [packs PR #73](https://github.com/tinylabscom/mvm-packs/pull/73)
  merged as `3af7fd2a1a6aaac6faf2333dddde235991e19dea`.
  Diagnostic source, signatures and byte bindings are not execution authority.
  Publication authorization remains an unconditional refusal.
- Application descriptor tooling:
  [packs PR #74](https://github.com/tinylabscom/mvm-packs/pull/74) merged as
  `5acbbe856be9a38df5903e4185ee04b224e7580b`. Application v2 has exactly five
  top-level fields: `schema_version`, `kind`, `reference`, `description`,
  `application`. It has no `files`, `image` or policy payload. Existing
  manifest-v1 policy packs and the root schema-2 catalog remain distinct.
- Lifecycle callback patch: scoped diff SHA-256
  `83f38094b7f4dc6b41c066ba6c0603c3f80be893c0e16a72d4781f52d251085e`,
  tested on `mvm` base `a926126bae1285a1b0e470428bb5a055bdd7b4bb`.
  The exact 12 expected unit tests passed, with zero failures or ignored tests.
  Source/lock pre/post checks matched. The runtime owner subsequently opened
  [draft PR #4469](https://github.com/tinylabscom/mvm/pull/4469) at
  `ed5cdb0d6a2ad18cc548d8a5e39ac05e2f84dc42`, reporting successful normal
  hooks and both stages of the required pre-push gate. Current-main integration
  and protected CI remain separate requirements.
- Those callbacks expose the actual admitted plan and backend stop result.
  They do not prove final-config custody, authenticated peer identity,
  physical cleanup or persistent stop/start.
- The private Claude archive passed producer health and consumer preboot
  verification/install. Its actual cold launch failed before VM creation
  because the consumer lacked the runtime overlay. It is not a ready fallback.
- Refreshed release dependencies: #4409 merged into main as
  `62f65b72318b83a108a56faa0c948e811b7a5eaa`, present in fetched main
  `911eb7143d89ec2bb2c30666f18c4eade0ac0697`. #4389 merged as
  `08e50ddebb6455df7e40a984965db82fdd7b3ba8` into
  `feat/image-boundary-integration`, not main; that commit is not an ancestor
  of the fetched main. Its portable closure contract still needs scoped
  integration. #4446 was last checked open at
  `ec6d7c0aad79024d9829c1904dd29a84e14071ea`. Latest promoted CLI checked here
  is v0.22.0; no compatible authenticated A/H/B closure has been accepted.
- [Packs #12](https://github.com/tinylabscom/mvm-packs/issues/12) has six
  unchecked production gates. PS-06/#3716 and the PS-06 box in #3731 stay open.

### Estimates, not promises

The runtime owner supplied these active-work planning budgets:

| Increment | Budget | Confidence and exclusions |
| --- | --- | --- |
| Normal hooks, isolated lifecycle commit and draft PR | 1–3 hours | Medium if no new findings; excludes unknown CI/queue wait |
| First persistent final-config/runtime-custody handoff | 4–8 hours | Low after dependency review; not the full semantic API |

Full transient/persistent observation, release A/H/B, hardware execution and
end-to-end acceptance remain unestimated. Do not present the sum above as a
completion ETA. Overall confidence in full public acceptance by Tuesday is
currently **low**.

## Relevant code and inherited contracts

- [Observer verifier](../../scripts/protected-observer-v2.py#L1): strict diagnostic report, client and
  candidate verification; future adapter must not infer measurement origin
  from its opaque mode artifacts.
- [Protected source loader](../../scripts/protected-observer-source.py#L1): fixed protected checkout inputs.
- [Canonical image stager](../../scripts/stage-image-release.py#L1): existing image-evidence verifier
  with optional source-bound signature verification.
- [Observer contract](../../docs/protected-observer-v2.md#L1): authority, policy, replay and live gates.
- [Python build intent](../../pack-sources/runtime/python/pack.toml#L1): x86_64 build intent, image-set/v0.2.4
  and exact signed root pin; verify immutability and current lock before use.
- [Observer tests](../../tests/test_protected_observer_v2.py#L1) and
  [source tests](../../tests/test_protected_observer_source.py#L1): source/byte/refusal regression tests.
- [Portable-runtime proposal review](../code-reviews/ps06-portable-runtime-proposal.md#L1):
  exact 14-file current-main packet, kernel-proof acceptance gap and missing
  genuine positive-runtime input. Source review is not cold-boot validation.
- Runtime owner's initial path map at public `mvm` source
  `83485b0d4c3fa291056b7177a0d4b42e28469693`:
  [entrypoint calls](https://github.com/tinylabscom/mvm/blob/83485b0d4c3fa291056b7177a0d4b42e28469693/crates/mvm-client/src/entrypoint/call.rs#L169)
  use the [observer trait](https://github.com/tinylabscom/mvm/blob/83485b0d4c3fa291056b7177a0d4b42e28469693/crates/mvm-client/src/entrypoint/dispatch.rs#L310);
  [generic foreground dispatch](https://github.com/tinylabscom/mvm/blob/83485b0d4c3fa291056b7177a0d4b42e28469693/crates/mvm-cli/src/commands/machine/runtime.rs#L680-L702)
  has a separate secure execution path;
  [persistent startup](https://github.com/tinylabscom/mvm/blob/83485b0d4c3fa291056b7177a0d4b42e28469693/crates/mvm-client/src/launch/persistent.rs#L405-L455)
  passes through boot/readiness/abort handling;
  [alternate local launch](https://github.com/tinylabscom/mvm/blob/83485b0d4c3fa291056b7177a0d4b42e28469693/crates/mvm-client/src/launch/mod.rs#L69-L90)
  returns admission but not complete final-config/runtime custody.
  These paths require separate verified coverage. KeepAlive is not evidence
  of generic persistent stop/start.

Read the exact current source and owner handoff before implementing. The
callback patch is not current-main integration merely because its old-base unit
run passed.
Portable-runtime integration must now use the fetched `911eb7143d` baseline and
review the changes from #4409, rather than treating the initial map as current.

## Dependency and execution plan

### P1. Land the bounded lifecycle increment

**Owner:** runtime/artifact. **Independent of:** artifact selection/hosting.

- Commit only the two reviewed client files, preserving unrelated checker WIP.
- Run normal formatting/Clippy hooks without bypass. The prepared normal-hook
  phase uses a fresh one-shot claim and a 595+5-second bound; it is a separate
  compute scope from the consumed 12-test run.
- Record actual hook exit, exact commit/diff and unchanged unrelated WIP.
- Open a normal PR and validate against current public main through protected CI.

**Exit:** reviewed two-file commit/PR and actual normal-check results. This
does not close the measurement-API gate.

### P2. Implement the real runtime observation/custody seam

**Owner:** runtime/artifact; observer owner reviews the consumer contract.

- First integrate the specifically reviewed portable release-runtime contract
  from #4389 against the new main containing #4409. Do not import the whole
  stale integration branch or assume schema-6 closure already exists on main.
- Before treating that integration as a demo unblock, resolve the canonical
  kernel-proof gap and identify a genuine positive runtime input/authority
  route recorded in the proposal review. A Release-only serializer cannot
  authorize the existing private Source bytes.
- Retain the same actual admitted plan and final consumed configuration/runtime
  custody at the last handoff before backend effects.
- Reuse the merged #4409 release-runtime verifier/custody implementation, not
  a new verifier, a SourceB substitute or a rejected source binder.
- Preserve artifact custody without extending a lifecycle lock across a stop
  path that reacquires it. A new generalized lease design is not this task.
- Keep signed image-set boot assets separate from CLI-owned runtime custody.
  Refuse an unbound SDK sidecar; LOCALDEV Source proof is never Release proof.
- Preserve backend-start, readiness, abort/rollback and stop uncertainty.
- Cover entrypoint, generic foreground, persistent start/restart/stop and
  alternate local launch paths. Explicitly mark unsupported paths unavailable.
- Expose actual command input/output/exit association and lifecycle outcomes
  where measured. Backend stop acknowledgement is not physical cleanup.
- Add mutation, substitution, missing-callback, no-dispatch, stop-failure and
  through-stop custody-lifetime tests.

**Exit:** one immutable, implemented in-process API, exact source/patch, compiled
test receipts and independent review. No guessed wire fields or success flags.
An applicable unobservable check blocks producer acceptance.

### P3. Build the observer adapter and protected backend policy

**Depends on:** P2's actual reviewed interface. **Owner:** observer/acceptance.

- Freeze the exact v2 producer contract against the implemented interface.
- Use fixed protected workflow policy bytes, source SHA equal to checked-out
  HEAD, and closed schemas/roles with no v1 downgrade.
- Capture actual process exits/raw streams and lifecycle observations for
  separate transient and persistent probes.
- Bind candidate, A/B, source/run/attempt, plan/final config/runtime, base/lock,
  policy and revocation/admission context.
- Missing, failed or unknown applicable observations refuse. N/A is permitted
  only by reviewed backend-specific policy.
- Test replay, stale attempts, mismatched contexts, altered bytes, missing
  measurements and every supported failure/cleanup path.

**Exit:** source and exact contract reviewed; producer workflow remains disabled
until the live prerequisites and execution authorization below are satisfied.

### P4. Establish compatible A/H/B and the exact Python candidate

**Owner:** runtime/artifact. Release preparation can overlap P2/P3.

- Close current release/runtime prerequisites and freeze release source.
- Authenticate producer A's repository/tag, archive, signed checksum entry,
  both bundles and exact executable member. Measure the executable SHA as H.
- Review/configure that one global H and release distinct compatible B.
  `None` refuses; do not introduce architecture-specific queries or fallback.
- First public live lane is Linux x86_64 A, Linux x86_64 B and x86_64 guest.
- Through the existing publisher, build the lock-pinned Python image twice
  and require byte identity. Retain its complete boot/runtime closure.
- Recheck the catalog before freezing the reference. Existing immutable
  versions are never overwritten; choose a new version if the intended one
  was published while this work was running.
- Freeze the actual sealed entrypoint and deterministic input/output probe.
  A version-only boot cannot satisfy workload I/O acceptance.
- Bind exact private candidate manifest, signature bundle, payload inventory
  and image evidence. B must use normal publisher, revocation, lock and Built
  admission checks on those exact bytes.

**Exit:** authenticated assets/pins plus exact reproduced candidate, not source
tests, policy-pack publication or a LOCALDEV archive.

### P5. Approve one concrete live execution manifest

**Depends on:** exact sources, commands and artifacts from P2–P4.

**Prepared by:** runtime/artifact with observer review. **Authorized by:** user.

Record source/CLI/helper hashes and features; kernel/runtime/initrd/verity
proofs; candidate/publisher/bundle fingerprints; policy/A/H/B/run bindings;
actual supported commands and expected I/O/exits; approved host and isolated
state; resource bounds, deadlines and identity-safe cleanup; network, transfer,
signing/publication and billable effects. Include any installer/channel effects
of release workflows. Read-only host availability is not an execution lease.

Every new validation phase has its own claim. No old grant, retry, stale READY
packet or permission inferred from this plan.

### P6. Protected observation, publication and fresh recipient

**Depends on:** P3–P5. **Owners:** runtime executes; observer accepts evidence.

- Protected B installs/adopts the exact private candidate, executes both modes
  and retains actual required measurements and failure cleanup.
- Verify the signed report's actual subjects and same-run/attempt bindings.
  Never sign an imported author verdict or infer security from configuration.
- Recheck current revocation/admission before publication.
- Publish the exact observed signed bytes through the canonical publisher.
  Any rewrite or re-sign requires re-observation.
- A clean recipient uses released B to pull, reverify, admit and run both modes,
  with expected input/output, plan/audit association and measured isolation/
  transport/cleanup. No producer cache seed or consumer package build.
- Check all six #12 gates, including lock-advance refusal/version behavior,
  against verifiable evidence before proposing acceptance updates.

**Exit:** public signed image-bearing pack and complete fresh-recipient witness.
Only this complete chain can close the relevant PS-06 acceptance.

## Claude demo track

The runtime/artifact owner owns the real runnable delivery path; the observer
owner checks the policy-interaction claims.

### Pack versus platform

The pack owns the pinned Claude binary/dependencies, application entrypoint and
headless prompt handling, provider-specific configuration, and declarations of
policy/secret requirements. None of those declarations is a host grant.

Policy definitions and reusable policy groups may live in both packs and host
configuration and compose with other policies. The user confirmed this hierarchy,
with precedence increasing to the right:

**bundle → user → optional `mvmd` policy**

`mvm` resolves and enforces that hierarchy itself. Without the optional
contribution, user policy takes precedence over bundle policy through the same
normal engine; no daemon or simulation is required. A lower-precedence layer
cannot override a higher-precedence decision or grant itself capabilities.
An incompatible required capability must refuse clearly.

For this demo, validate actual bundle-versus-user composition and refusal.
Later `mvmd` work supplies the optional higher-precedence input to the existing
engine; do not invent a separate policy engine or block standalone validation
on that integration.

This workload-policy hierarchy does not permit pack/user verdicts to replace
the observer's fixed protected-source backend measurement policy.

The platform owns generic authenticated pull/install/admission, verified runtime
and kernel custody, policy composition/enforcement, authorized host secret
brokering and network transport, and session input/output/exit/cleanup. Missing
generic support belongs in `mvm`; do not add Claude-specific core branches,
another builder or a credential bypass.

### Required demonstration

1. Integrate and validate the preserved application resolver against the merged
   application-v2 descriptor contract. Freeze the pack version and actual
   supported command grammar before rehearsal.
2. Produce a replacement self-contained `anthropic/claude` bundle through the
   supported exporter, with actual reviewed kernel/runtime/purpose custody.
   Do not reuse the old failing archive's health result for new bytes.
3. Establish an authorized descriptor signer, namespace policy and delivery
   locator. The name grants no default Anthropic trust. A bundle key ID is an
   assertion; independently verify it through the existing trust store.
4. Pull the pinned pack through the actual registered application path on a
   clean consumer: download/verify/install only, no hidden build/bootstrap/cache
   seed. Local bundle installation alone is not a successful named-pack pull.
5. Show the loaded pack policy and effective host restrictions using a safe
   redacted projection, not raw secret-bearing plans.
6. Configure the pack's declared unprivileged entrypoint for an actual bounded
   headless prompt. Verify the exact pinned CLI's supported input/model options;
   do not present hypothetical `mvmctl` commands as a released interface.
7. Use the existing `mvm` host-held credential-secret mechanism, as confirmed by
   the user. The pack declares the authorized secret requirement/reference;
   `mvm` controls its use and provider-side substitution. The microVM must not
   receive the real provider key in its image, environment, files, arguments or
   logs. Confirm actual Claude proxy/header-substitution behavior; configured
   variables alone are not proof. Never mount host login files or log
   secret-bearing plans/headers. Do not build a new vendor credential store.
8. Under an allowed policy, submit a non-sensitive prompt and receive an actual
   model response. Record the real input/output/exit and plan/audit association.
   This is required for the requested demo, not an optional enhancement.
9. Apply a deliberate restrictive personal policy and demonstrate the actual
   admission/network refusal with its reason. Prefer a required-capability
   admission refusal before a paid request where the implemented contract
   supports it. Requirements are not grants; local restrictions win.
10. Rehearse actual I/O and confirmed cleanup for every claim made in the demo.
    Version/help output remains diagnostic, not a substitute for the real prompt
    or evidence of policy enforcement.

The user has selected a real prompt and the existing host-held secret route,
and approved a **maximum of USD 5 total** for model usage across validation,
rehearsals and the demo combined. This is not a per-run budget and may not be
raised automatically.

Use supported, verified CLI/provider request and budget controls plus one shared
redacted spend ledger. Record the exact model, limits and cumulative usage.
Do not claim an enforced cap until the controls have been tested. If the next
request cannot be bounded within the remaining balance, stop before issuing it.
Paid retries count against the same cap; none are automatically authorized.

Live calls still require working Claude/host-broker compatibility, configured
request limits and the secret supplied through the supported secure store,
never chat or committed files. The budget does not authorize cloud provisioning,
new credential stores, public redistribution, signing or publication.
Subscription/browser login is unproven and must not be assumed available.
Public Claude redistribution or official endorsement is not authorized by the
demo name or this plan.
If the supported named-pack path is not ready, label any local preview
accurately; never rename bundle-install success as pack-pull acceptance.

### Friday noon: concrete feasibility evidence

Present two explicit assessments: public PS-06 acceptance and the standalone
Claude demo. Neither status may borrow the other's evidence.

- Pin the actual implementation, CLI/helper, runtime/kernel proof and candidate
  identities. Separate source-only, compiled, tested and live results.
- Show that the replacement exporter includes the verified runtime closure.
  Repeating the old archive's already-known missing-overlay failure is not
  validation of a replacement.
- Report the latest actual cold-consumer attempt and named-pack pull status,
  with command, numeric exit and retained logs. If a stage is unrun, name the
  exact missing code/API/artifact/authority rather than reporting green readiness.
- Record the working host-secret path, provider compatibility and controls for
  the cumulative USD 5 limit.
- Supply the exact next bounded native validation manifest for review before
  execution. Do not invent runtime authority or bypass a check to meet noon.

### Sunday: demo validation must pass all four cases

| Case | Required actual evidence |
| --- | --- |
| Pull and cold start | Named pinned pack, descriptor/archive identity and trust verification; clean consumer state; actual application startup without package build, source bootstrap or producer-cache seed |
| Allowed prompt | Real Claude prompt/model response and exit, tied to the same pack/plan; verified host-only credential path and recorded model usage within the shared budget |
| Personal-policy refusal | Same pack identity under the restrictive personal policy; actual refusal and reason/audit association, not merely displayed policy configuration |
| Cleanup and repeatability | Owned runtime resources accounted for after teardown, fixed artifact/commands/policies, and a repeatable rehearsal; backend stop acknowledgement alone is insufficient |

No `mvmd`, organization-policy, interactive terminal, startup SLO or public
Claude-distribution claim is needed for this standalone demo. Trust, runtime
custody, policy enforcement and credential isolation are not deferred.
These four cases validate the demo only; public PS-06 acceptance still requires
P1–P6 and both public lifecycle modes.

## Calendar checkpoints

These are target decision deadlines, not predicted completion dates.

| Deadline, Pacific | Required checkpoint | If missed |
| --- | --- | --- |
| Thu Oct 15 evening | P1 progresses with real hook/PR evidence; remaining API/release tasks have explicit ownership | Report actual failure/unknowns, preserve state and revise the next bounded task |
| Fri Oct 16, 12:00 | Separate public/demo feasibility decisions using the concrete evidence checklist above | Do not promise unproven acceptance; report the exact failed or unrun stage and its next bounded action |
| Fri Oct 16 evening | API and public-mode coverage frozen/compiled or specific remaining failures exposed; live authorization packet taking shape | Keep workflow disabled; escalate concrete missing evidence, not generic green status |
| Sat Oct 17 | Target authenticated A/H/B, reproduced candidate, reviewed observer adapter and approved live manifest | Public target becomes no-go unless a revised evidence-backed schedule preserves rehearsal time |
| Sun Oct 18, 09:00 | Target all four actual standalone demo cases above; track public protected/fresh-recipient acceptance separately | Do not substitute compilation, source-only or version output for the real demo |
| Mon Oct 19 | Full demo rehearsal and artifact/command freeze; verify current revocation/admission | Rebuild/re-sign means re-observe and re-rehearse; no last-minute bypass |
| Tue Oct 20 before 09:00 | Approved final preflight of exact hashes, trust freshness, state and commands | Refuse expired/revoked/mismatched inputs; present only already-proven claims |

## Validation and evidence discipline

Observer source changes use:

```sh
python3 -m unittest tests.test_protected_observer_v2 tests.test_protected_observer_source
python3 -m unittest discover -s tests
python3 scripts/validate-packs.py
ruff check scripts/protected-observer-v2.py scripts/protected-observer-source.py tests/test_protected_observer_v2.py tests/test_protected_observer_source.py
ruff format --check scripts/protected-observer-v2.py scripts/protected-observer-source.py tests/test_protected_observer_v2.py tests/test_protected_observer_source.py
git diff --check
```

Runtime validation must use its individually approved exact phase packet,
including source/lock hashes, selected test inventory, numeric exit, logs,
timeouts and process cleanup. An all-filtered run is failure. Signature mocks,
contract tests and compilation remain distinct from genuine signatures, native
execution, protected observation and public fresh-recipient acceptance.

Store receipts durably. Record every gate as source-only, compiled/unit-tested,
live/private, protected/public, failed or unavailable. Never mark a later gate
complete merely because an earlier one passed. The observer owner maintains
this ledger; the runtime owner supplies actual artifacts and execution evidence.

## Remaining decisions and restrictions

- The user selected Python for public acceptance and `anthropic/claude` as the
  real-prompt policy-interaction demo. The exact Claude pack version, authorized
  delivery/signing scope, working host-secret binding, enforced model/request
  limits and executable commands still require the concrete handoff above.
- No complete measurement receipt wire is frozen by this document.
- Full public completion by October 20 remains low-confidence until the Friday
  feasibility gate closes. The plan does not quietly reduce the acceptance bar.
- No architecture reapproval is requested. Concrete live/signing/publication,
  transfer, credential or billable authority is requested only with its exact
  execution manifest.

## Amendments

- 2026-10-15: the user made a real Claude prompt/response a required demo
  outcome. Offline/version checks are no longer the demo baseline. Pack-specific
  configuration and generic platform responsibilities are separated above;
  authentication and model-spend authorization remain explicit execution gates.
- 2026-10-15: the user confirmed composable policy definitions in both pack and
  host, with `mvm` enforcing the effective policy, and selected the existing
  host-held credential-secret mechanism. Raw provider credentials must not enter
  the microVM. Model/request limits and spending authority remain unapproved.
- 2026-10-15: the user fixed application-policy precedence as organization policy
  through `mvmd` above personal policy above pack policy, and approved USD 5
  maximum total model usage for validation, rehearsals and the demo. Execution
  still requires working secret integration and verified request/budget controls;
  no other authority is expanded.
- 2026-10-15: the user excluded `mvmd` from the demo and requested actual Friday
  feasibility evidence and a real Sunday demo. The standalone policy comparison
  is pack versus personal; managed organization-policy work is post-demo. Added
  concrete cold-consumer, prompt, refusal and cleanup validation cases without
  relaxing the separate public PS-06 acceptance gates.
- 2026-10-15: the user clarified that `mvm` enforces the hierarchy
  bundle → user → optional `mvmd` policy itself. Removed wording that incorrectly
  required a daemon path for policy validation. Standalone composition is the
  real product behavior, not a simulation or deferred implementation.
- 2026-10-15: independently verified #4409 is merged into current main, while
  #4389 merged only into the integration branch. Corrected the source dependency:
  select and integrate its portable closure contract against main with #4409;
  neither PR state alone nor an old integration branch proves current support.
