# Runnable application declarations

## Implemented structure, not publication approval

`pack/application.json` is an ordinary signed file: the existing registry
manifest file table binds its exact digest and length. Neither the manifest
schema nor the catalog schema changes. A declaration requires the separately
listed, signed `pack/profile.toml`.

The strict declaration has exactly `schema_version` (integer `1`) and
`archives` (a nonempty object keyed only by `aarch64` or `x86_64`). Each archive
has exactly:

| Field | Requirement |
| --- | --- |
| `url` | HTTPS release download asset on `github.com`, with owner, repository, release tag and asset; no credentials, nondefault port, query or fragment; tag is not `latest` |
| `sha256` | 64 lowercase hexadecimal characters |
| `size_bytes` | Integer, not boolean, from 1 through 4294967296 |
| `key_id` | Expected archive publisher key ID, 32 lowercase hexadecimal characters |

The declaration is limited to 65536 bytes; the signed profile must contain
1 through 1048576 bytes. Release assets must be treated as immutable,
versioned artifacts; metadata validation does not prove server immutability.
Digest and size bind the downloaded bytes.

The shared producer validator runs in source builds and registry validation.
The normal builder validates runnable declarations and then **refuses
publication** before generic file signing. Protected archive signing and
authorized final archive/evidence integration are still required. Existing
source-image publication guards remain in place. This change publishes no
application pack, source, version, archive or approval.

The archive consumer and policy transport do not finish target application
production. The neutral Rust authoring command `mvmctl pack prepare` verifies
the pinned upstream archive, executable digest, architecture and interpreter,
then stages the executable through the existing local-source resolver and
frozen compiler. Candidate inputs and launcher data live beside the existing
policy source, outside its published payload. They are not a published version.

`mvmctl pack build` rechecks that lock and uses the existing builder-VM
materializer to produce an exportable image slot. The generated development
variant is explicitly selected with `--profile dev`; default images remain
sealed. Both receive an integrity hash tree before export; development
accessibility remains a separate, unchanged sidecar setting. Native source
bytes are not stripped or patched. An explicit runtime
package request for `glibc` supplies its interpreter and library links in the
image, rather than installing them at startup.

The existing `bundle export` path accepts the environment and exact profile
along with authenticated boot assets. A materialized loader closure, authorized
archive signing, and protected publication evidence are still required. No
final target archive or successful application boot is established by these
authoring commands.

Validation built the target native image and checked the executable against
its pinned digest, interpreter and library files. A locally signed development
candidate passed signature verification and generic bundle installation; an
altered rootfs payload was refused. These are not registry publication or
application-launch evidence.

These validation results describe the preserved source snapshot and its
changes, not current upstream delivery status. Upstream has since added a
portable runtime-closure connection and later application-delivery work.
Reconcile this prototype with those implementations before promoting it.

The actual launch attempt exposed a runtime compatibility blocker: the locked
`image-set/v0.2.4` runtime member is version `0.22.0` and lacks the required
`/tool-shim`. The launch validator refused it before application execution.
Export now uses that same payload validator before signing, and runnable pulls
validate the staged runtime before promoting an installation or name pin.
Installed lookup rechecks the runtime without reinstalling the application.
Do not replace bytes under the old signed image-set identity or disable its
payload checks. A compatible CLI-owned full runtime and the protected producer
connection are still required before the intended demonstration can be ready.

## Independent trust boundaries

The registry manifest uses its existing Sigstore publisher verification.
The `.mvmpkg` archive independently requires the existing Ed25519 archive
verifier and publisher trust. A registry signature is not a substitute for
that archive signature, nor does either signature grant local execution
approval.

The archive's `environment.pack` must equal the exact registry reference.
Its ordinary artifact named `policy/profile.toml`, stored at
`artifacts/policy/profile.toml`, must match the signed registry profile's size,
digest and exact bytes. The full boot closure must be sealed
through the protected producer path. A passing host structure check proves
none of the archive signature, closure, boot, or local approval requirements.

## Future operator rehearsal

No runnable application is currently published in this registry. For a future
authorized rehearsal, the operator must supply the exact reference from a real
signed declaration, rather than substitute a policy-only pack or an invented
release:

```sh
: "${APPLICATION_PACK_REF:?Set the exact reference from the real signed declaration}"
: "${MVM_HOME:?Use private demo state configured with independently approved trust inputs}"
: "${LOCAL_APPROVAL_POLICY:?Set the local policy approving the required capabilities}"
mvmctl pull "$APPLICATION_PACK_REF"
mvmctl run "${APPLICATION_PACK_REF%@*}" --profile dev -it --policy "$LOCAL_APPROVAL_POLICY"
```

These are development-demo commands, not evidence that they have succeeded.
Prepare a new private state directory and application cache, independently
approve the archive publisher key, and configure current independent revocation
trust before pull. Runnable declarations require freshness/revocation checks;
they cannot use the policy-only pack's optional-feed behavior. Bootstrap the
compatible standalone client and its signed host/runtime prerequisites without
application author sources or startup-time application downloads.

Follow the compatible client's approval and launch documentation after pull.
Local approval remains a separate operator policy decision. A signed Dev
archive may explicitly use `--profile dev -it` for the existing development-only
interactive terminal. Never fall back to Dev or unseal a SealedProd archive
to obtain a terminal. Production owner-mediated message passing remains
deferred under issue #4460; a sealed production interactive terminal is not
provided by this declaration.
