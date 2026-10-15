# PS-06 protected observer diagnostic v2 review

## Initial scope at `35faa9a4e10225ab48f84d745117605b11d49029`

Before this review artifact: 5 files, 2 modified, 3 added, 0 deleted;
1,652 inserted lines and 3 deleted lines.

This review concerns an import-only diagnostic subset, not the completed
producer contract. `require_publication_authorization` always refuses.
No workflow, runtime, release, image recipe or published registry file changed.

## Findings addressed

1. **Candidate verifier binding:** the first integrated regression showed
   that a declared candidate pin was not checked against payload provenance.
   The verifier now compares H and reconstructs the existing canonical
   publisher provenance statement, checking rootfs subject, reference, base
   set, builder, protected source commit and run/attempt invocation.
2. **Signed-input archive resource bound:** independent review demonstrated
   that `tarfile` consumed PAX/GNU extension bodies before yielding members,
   allowing a 1 GiB declared read before validation. The parser now inspects
   fixed 512-byte headers, rejects extensions before body reads, bounds the
   exact executable and trailer, and never extracts filesystem paths.
   Regression coverage proves extension headers are rejected after a single
   512-byte decompressed read.
3. **Role/subject separation:** unsupported image-evidence/report roles refuse
   rather than exposing an identity-only successful signature check. Enabled
   release and candidate roles require fixed subject/bundle filenames;
   canonical candidate contents receive separate semantic/inventory checks.
4. **Protected registry selection:** registry bytes are independently pinned
   from selected document bytes; both schemas are closed, selector duplicates
   refuse, and source/role/backend/version must agree.

## Initial integration limitations

- No runtime receipts, measurement semantics, production backend acceptance
  policy, or protected source loader is implemented. Caller-owned workflow SHA
  and policy bytes are trusted inputs, not authenticated by structural parsing.
- Candidate/layer/lock digests in provenance remain declared dependencies;
  no complete independent base/lock/revocation/admission proof is supplied.
- Candidate payload bytes are checked but no usable immutable transport
  snapshot is returned. Later reads/import/publication of the original
  directory require a fresh owned snapshot and revalidation.
- Filesystem failures may raise `OSError` subclasses rather than `WitnessError`.
  They still refuse; any future integration must not catch them as success.
- No standalone signed observer report/full image-evidence verification
  pipeline or publication capability exists.

## Evidence

- `python3 -m unittest tests.test_protected_observer_v2`: 31 passed.
- `python3 -m unittest discover -s tests`: 292 tests, 1 skipped, successful.
- `python3 scripts/validate-packs.py`: 9 manifests validated.
- Ruff format/lint on both new Python files and `git diff --check`: clean.
- First independent reviewer performed a pure-memory archive-parser resource
  reproduction, read source/tests/docs, and made no edits.
- Fresh independent review found no concrete remaining correctness or fail-open
  issue in this diagnostic subset and independently reran all 31 focused tests.
  The reviewer additionally built compressed archives with actual 8 MiB
  PAX/GNU extension bodies: each refused after exactly one 512-byte read.
  An independently constructed valid bounded USTAR archive with an optional
  parent directory returned the exact executable bytes.

These tests use synthetic byte fixtures and mocked cryptography. They are not
real-release signature verification, protected execution, Built admission,
runtime acceptance, public publication or fresh-recipient evidence.

## Follow-up: protected source and composed diagnostic verification

The integration owner authorized completing the non-runtime source/image
boundary while explicitly forbidding guessed receipt APIs and producer
enablement.

Implemented after the initial review:

- Fixed-path policy loading tied to trusted `GITHUB_WORKFLOW_SHA`, actual HEAD,
  a clean checkout, fixed regular committed workflow/registry/document bytes,
  and no index flags concealing tracked changes. Git routing variables and
  replacement objects do not select alternate source; immutable commit IDs,
  not moving HEAD, select blob content.
- `verify_diagnostic` composes strict source/report validation, A/B archives,
  canonical candidate, existing image evidence and exact lock/current-run
  provenance, plus a signed diagnostic envelope. All nine signed subjects are
  checked against their fixed role/subject and identity, with publisher source
  SHA extensions for image/candidate/diagnostic signatures.
- The canonical stager accepts an optional source-bound signature callback;
  its default publisher behavior is unchanged. No second publisher exists.
- Existing metadata versions and file records receive exact v2 numeric rules;
  no bool/float coercion through legacy JSON equality.

Latest checks:

- `python3 -m unittest tests.test_protected_observer_v2 tests.test_protected_observer_source`:
  50 passed, including mini-Git source-boundary and mock signature/source
  pipeline tests.
- `python3 -m unittest discover -s tests`: 311 tests, 1 skipped, successful.
  An earlier 200-second invocation timed out without a result; a fresh exact
  command with a longer execution bound completed successfully in 76.970 s.
- `python3 scripts/validate-packs.py`: 9 manifests validated.
- Ruff format/lint on the four observer/source Python files, lint on the changed
  canonical stager, and `git diff --check`: clean.
- Independent follow-up review found no additional concrete security bug in
  the remaining diagnostic pipeline. Its isolated snapshot passed 10 source
  tests and 38 observer tests, with mocked source/signature authority. That
  snapshot predated the immutable Git-ref/fsmonitor/timeout/exact-type fixes;
  it did not independently verify those final fixes. A separate narrow review
  of those exact fixes at `8ca217656c0e94c219f4da2c1df46fb7130e76b9`
  subsequently found no additional concrete bug.
- The final reviewer passed four focused committed tests and independently
  instrumented immutable Git SHA arguments, routing sanitization, disabled
  fsmonitor/replacements, deadlines and timeout refusal. Sixteen supplemental
  bool/float size mutations across metadata record families refused. These
  supplemental checks were in-memory review evidence, not new committed tests;
  committed coverage does not directly assert every Git flag/deadline or every
  metadata size-family/float combination.

Superseded limitations: protected source loading and existing-image/diagnostic
signature composition are now implemented. The loader does not authenticate an
arbitrary environment dictionary; its input must be the trusted protected job
environment. No production policy files, runtime measurement semantics,
reviewed receipt DTO, producer, publication capability, or live witness exists.
Transient/persistent files remain opaque bound bytes, not runtime observations.
No retained candidate transport snapshot is returned for later import or use.
Current consumer revocation/admission and B's actual compiled-lock acceptance
remain separate live requirements, not established by matching supplied lock
bytes.
