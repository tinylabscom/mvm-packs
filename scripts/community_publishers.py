"""Strict reader for community/publishers/<owner>.toml reference files (ADR 002).

A reference names the author's own repository and workflow; it carries no pack
payload. The registry never signs community packs.
"""

import re
import tomllib
from pathlib import Path

RESERVED = frozenset({"mvm", "agent", "runtime"})
OWNER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\Z")
NAME = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z")
REF = re.compile(r"refs/(?:tags|heads)/[A-Za-z0-9._/-]+\*?\Z")
FIELDS = {"repository", "workflow", "ref_pattern", "environment", "packs"}


def validate_reference(owner, data):
    """Raise ValueError unless `data` is a safe reference for namespace `owner`."""
    if not OWNER.fullmatch(owner) or owner in RESERVED:
        raise ValueError(f"{owner!r} is not a usable community namespace")
    if not isinstance(data, dict) or set(data) - FIELDS or {"repository", "workflow", "ref_pattern", "packs"} - set(data):
        raise ValueError("reference must have repository, workflow, ref_pattern, packs and optional environment")
    repository = data["repository"]
    # Namespace must equal the signing repository's owner (as nono enforces at pull).
    if not isinstance(repository, str) or repository.partition("/")[0].lower() != owner \
            or not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be <owner>/<repo> with the owner equal to the namespace")
    if not isinstance(data["workflow"], str) or not WORKFLOW.fullmatch(data["workflow"]):
        raise ValueError("workflow must be a file under .github/workflows/")
    ref = data["ref_pattern"]
    if not isinstance(ref, str) or not REF.fullmatch(ref) or ref.count("*") > 1 or ".." in ref:
        raise ValueError("ref_pattern must be refs/tags/ or refs/heads/ with at most a trailing *")
    if ref.rstrip("*") in ("refs/tags/", "refs/heads/"):
        raise ValueError("ref_pattern must name a prefix, not every tag or branch")
    environment = data.get("environment", "")
    if not isinstance(environment, str) or not re.fullmatch(r"[A-Za-z0-9._-]*", environment):
        raise ValueError("environment must be a GitHub environment name or empty")
    packs = data["packs"]
    if not isinstance(packs, list) or not packs or len(set(packs)) != len(packs) \
            or not all(isinstance(p, str) and NAME.fullmatch(p) for p in packs):
        raise ValueError("packs must be a non-empty list of unique pack names")
    return data


def validate_directory(directory):
    """Return a list of problem strings for every reference under `directory`."""
    problems = []
    directory = Path(directory)
    if not directory.is_dir():
        return problems
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or path.suffix != ".toml":
            problems.append(f"{path}: only regular <owner>.toml files are allowed")
            continue
        try:
            validate_reference(path.stem, tomllib.loads(path.read_text(encoding="utf-8")))
        except (ValueError, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            problems.append(f"{path}: {error}")
    return problems
