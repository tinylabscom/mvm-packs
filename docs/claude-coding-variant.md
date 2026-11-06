# Plan: a coding variant of the Claude application pack

Status: planned, not built. Not a claim that any archive exists or is published.

Related: [CLAUDE-ENVIRONMENT.md](../CLAUDE-ENVIRONMENT.md), [ADR 003](adr/003-embedded-requirements.md),
[#31](https://github.com/tinylabscom/mvm-packs/issues/31), [#67](https://github.com/tinylabscom/mvm-packs/issues/67).

## Why a separate pack

`agent/claude@2.0.0` is the restricted demo: `mvm-agent --allowedTools WebFetch
--max-turns 3 --max-budget-usd 0.50`, egress only to `api.anthropic.com:443`. A
coding agent needs more tools and a wider egress ceiling. Folding that into the
demo would enlarge its signed digest and permissions for everyone, so the coding
variant is its own pack: **`agent/claude-coding`** (a first-party name, reserved
namespace), its own versions, its own descriptor, its own signed ceiling.

## What it adds to the demo closure

Observed in the draft demo archive (read with `debugfs`, 2026-11-06): bash,
coreutils, busybox, glibc, musl, gcc runtime libraries, and
`/etc/ssl/certs/ca-certificates.crt` are already there. Missing for repo work:

| Need | Why | Status |
| --- | --- | --- |
| `git` | clone, diff, commit; a coding agent without it is crippled for repo work | add |
| ripgrep | Claude's search. The embedded binary is the **musl** build, and the vendor's setup page says musl builds need a system `ripgrep` with `USE_BUILTIN_RIPGREP=0` | add, and set the variable |
| `curl`, `node`, `python3`, `jq` | only if an agent tool or bundled helper shells out to them | do not add speculatively |

Anything beyond `git` is found empirically (below), not guessed: every added tool
is attack surface in a sealed root filesystem and enlarges the signed digest.

## Decisions that change the signed descriptor

- **Egress ceiling.** The demo allows `api.anthropic.com:443` only. Cloning needs
  at least `github.com:443` (and the hosts GitHub redirects to). The ceiling is
  signed, binds the user, and can only be narrowed locally, so each added host is
  a deliberate decision. Start from the smallest set that makes the acceptance
  workload pass.
- **Secrets.** `ANTHROPIC_API_KEY` (required) as today; an optional
  `GITHUB_TOKEN` slot for private repos. Names only; the host substitutes values.
- **Getting code into the guest.** A pack cannot add a host share (policy rule),
  so the agent clones over the network into `/work`, or the user grants a share at
  run time. Which one is the default is undecided.
- **Entrypoint and limits.** The demo is one-shot and capped at 3 turns and
  $0.50. A coding session needs larger or user-set limits; the signed ceiling
  should stay a maximum, not the default.

## Acceptance (empirical, before any signing)

Boot the draft root filesystem through the builder and consumer path and run the
workload class; record every command that fails with "not found". At least:
`git --version`; a clone from an allowed host; a Claude search; a Bash-tool
command; an edit and `git diff`; a refusal when a host outside the ceiling is
requested. The result list becomes `[requirements]` (ADR 003), checked before
the descriptor is signed.

## Dependencies and owners

- Build recipe, builder custody and the live boot test belong to the MVM
  runtime/artifact owner (PS-06); this repository does not touch those files.
- Redistribution of the Claude binary needs approval recorded in #31, as for the
  demo. Nothing here grants it.
- The archive must pass the registry gate (digest, kernel and rootfs, signature,
  and ADR 003 requirements once implemented) before its descriptor is signed.
- Version: the demo archive embeds Claude Code 2.1.273 while
  `environment-inputs.json` pins 2.1.312. The coding variant needs one agreed
  version.

## Open questions

- The exact egress hosts, and whether `GITHUB_TOKEN` is in scope for v1.
- Default way to get code in (clone versus share).
- Whether the variant ships on both `aarch64` and `x86_64` (one descriptor per
  architecture, so two versions or two names).
