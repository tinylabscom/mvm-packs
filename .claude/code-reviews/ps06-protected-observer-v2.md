# PS-06 protected observer diagnostic v2 review

## Scope

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

## Explicit remaining integration limitations

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
