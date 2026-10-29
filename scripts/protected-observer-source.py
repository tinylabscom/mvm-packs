#!/usr/bin/env python3
"""Fixed protected checkout inputs for diagnostic v2 policy resolution only."""

import importlib.util
import os
from pathlib import Path
import re
import subprocess


_spec = importlib.util.spec_from_file_location(
    "protected_observer_v2", Path(__file__).with_name("protected-observer-v2.py")
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("required v2 helper unavailable")
v2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v2)
WitnessError = v2.WitnessError
ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ".github/policies/protected-observer-registry-v2.json"
WORKFLOW_PATH = ".github/workflows/publish.yml"


def load_source(environment):
    """Load workflow-owned diagnostic inputs; no author paths or bytes accepted.

    ``environment`` must be the trusted GitHub job environment, not report or
    dispatch fields. This function checks consistency, not its authentication.
    Returns source, checkout_sha, workflow_sha, trusted_registry (bytes), and
    trusted_policies (the exact tuple-keyed lookup accepted by resolve_policy).
    No runtime acceptance or publication authorization is provided.
    """
    root = ROOT
    source = v2.source_identity(environment)
    workflow_sha = environment.get("GITHUB_WORKFLOW_SHA")
    if (
        not isinstance(workflow_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", workflow_sha) is None
        or workflow_sha != source["sha"]
    ):
        raise WitnessError("workflow SHA must equal protected source SHA")

    # Never let inherited Git routing/config variables select another checkout,
    # index, object store, or replacement object.
    git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    git_env["GIT_NO_REPLACE_OBJECTS"] = "1"

    def git(*args):
        try:
            return subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
                env=git_env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise WitnessError("protected checkout Git check failed") from error

    def checkout():
        if git("rev-parse", "--show-toplevel").decode().strip() != str(root):
            raise WitnessError("script root is not the repository toplevel")
        sha = git("rev-parse", "HEAD").decode().strip()
        if sha != workflow_sha:
            raise WitnessError("checkout HEAD differs from workflow SHA")
        if any(
            entry[:1] != b"H"
            for entry in git("ls-files", "-v", "-z").split(b"\0")
            if entry
        ):
            raise WitnessError("index flags can hide tracked source changes")
        if git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ):
            raise WitnessError("protected source checkout is dirty")
        return sha

    checkout_sha = checkout()

    def read_fixed(path):
        try:
            raw = v2.bounded_bytes(root / path)
            tree = git("ls-tree", workflow_sha, "--", path).decode()
            if not tree.startswith(("100644 blob ", "100755 blob ")):
                raise WitnessError("protected input is not a regular HEAD blob")
            size = int(git("cat-file", "-s", f"{workflow_sha}:{path}"))
            if not 0 < size <= v2.LIMIT or size != len(raw):
                raise WitnessError("protected HEAD blob exceeds bound or differs")
            if git("cat-file", "blob", f"{workflow_sha}:{path}") != raw:
                raise WitnessError("protected input differs from HEAD bytes")
            return raw
        except (OSError, ValueError) as error:
            raise WitnessError("protected source file unavailable") from error

    read_fixed(WORKFLOW_PATH)
    registry_raw = read_fixed(REGISTRY_PATH)
    document_raw = read_fixed(v2.POLICY_PATH)
    # Fixed document metadata supplies the selector; resolve_policy validates
    # the complete registry, every selector, digest, and document schema.
    document = v2.parse_json(document_raw)
    v2.shape(
        document, {"schema_version", "role", "backend", "version"}, "policy document"
    )
    binding = {
        "path": v2.POLICY_PATH,
        "role": document["role"],
        "backend": document["backend"],
        "version": document["version"],
        "source": source,
        "document": v2.digest(document_raw),
        "registry": v2.digest(registry_raw),
    }
    # Validate untrusted selector types before using them as mapping keys.
    if (
        not isinstance(document["role"], str)
        or not isinstance(document["backend"], str)
        or type(document["version"]) is not int
    ):
        raise WitnessError("invalid document selector")
    key = (
        v2.POLICY_PATH,
        document["role"],
        document["backend"],
        document["version"],
        source["repository"],
        source["ref"],
        source["sha"],
        source["workflow_ref"],
        binding["document"]["sha256"],
    )
    policies = {key: document_raw}
    v2.resolve_policy(binding, policies, source=source, trusted_registry=registry_raw)
    checkout()
    return {
        "source": source,
        "checkout_sha": checkout_sha,
        "workflow_sha": workflow_sha,
        "trusted_registry": registry_raw,
        "trusted_policies": policies,
    }
