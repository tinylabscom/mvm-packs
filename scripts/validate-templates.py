#!/usr/bin/env python3
"""Validate registry payloads; signed-pack trust is still checked by mvmctl."""

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PACK_REF = re.compile(r"([a-z0-9_-]+)/([a-z0-9_-]+)@([0-9]+\.[0-9]+\.[0-9]+)")


def local_file(base, relative):
    """Require a regular, non-symlink payload inside its declared directory."""
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ValueError(f"unsafe template path: {relative}")
    full = base / path
    if not full.is_file() or not full.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"missing or unsafe template file: {relative}")
    current = full
    while current != base:
        if current.is_symlink():
            raise ValueError(f"missing or unsafe template file: {relative}")
        current = current.parent
    return full


def validate_profile(root, template, relative):
    profile = tomllib.loads(local_file(template, relative).read_text())
    if set(profile) != {"description", "extends"}:
        raise ValueError("runtime profile must only describe and extend a signed pack")
    reference = profile["extends"]
    match = PACK_REF.fullmatch(reference) if isinstance(reference, str) else None
    if not match:
        raise ValueError("profile requires an exact-version signed pack reference")
    namespace, name, version = match.groups()
    if namespace != "agent" or template.name != f"agent-{name}-runtime":
        raise ValueError("runtime scaffold selects the wrong agent profile")
    bundle = root / "packs" / namespace / name / version
    manifest = json.loads(local_file(bundle, "manifest.json").read_text())
    local_file(bundle, "manifest.sigstore.json")
    if manifest["reference"] != reference:
        raise ValueError("pack manifest reference mismatch")
    entry = next(
        (file for file in manifest["files"] if file["path"] == "pack/profile.toml"),
        None,
    )
    if entry is None:
        raise ValueError("referenced pack does not export a profile")
    payload = local_file(bundle / "files", entry["path"]).read_bytes()
    if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
        raise ValueError("signed profile payload digest mismatch")


def validate(root=ROOT):
    entries = json.loads((root / "index.json").read_text())["templates"]
    names = set()
    for entry in entries:
        if entry["name"] in names:
            raise ValueError(f"duplicate template: {entry['name']}")
        names.add(entry["name"])
        metadata = local_file(root, f"{entry['path']}/template.toml")
        template = metadata.parent
        meta = tomllib.loads(metadata.read_text())
        if meta["name"] != entry["name"] or meta["description"] != entry["description"]:
            raise ValueError("index and template metadata disagree")
        flake = local_file(template, "flake.nix").read_text()
        files = meta.get("files", [])
        for relative in files:
            local_file(template, relative)
        policy = meta.get("policy", {})
        if "profile" in policy:
            local_file(template, policy["profile"])
        if entry["name"].startswith("agent-"):
            if entry.get("mvm_version") != ">=0.24.0":
                raise ValueError("runtime scaffold requires the policy-aware template consumer")
            if not entry["name"].endswith("-runtime") or "no agent client installed" not in meta["description"]:
                raise ValueError("agent runtime scaffold must disclose its scope")
            if policy != {"profile": "policy/profile.toml"}:
                raise ValueError("agent runtime scaffold must select its local profile only")
            validate_profile(root, template, policy["profile"])
            required = {"app/check-runtime.sh", "SETUP.md"}
            if not required.issubset(files):
                raise ValueError("runtime app and setup instructions must be downloaded")
            actual = {str(path.relative_to(template)) for path in (template / "app").rglob("*") if path.is_file()}
            if not actual.issubset(files):
                raise ValueError("app file omitted from download metadata")
            if "entrypoint.command" not in flake or "services." in flake:
                raise ValueError("runtime scaffold requires the supported command entrypoint")
            if re.search(r"\$(anthropic|openai)", flake):
                raise ValueError("invented secret environment substitution")
            for name in ("mvm", "nixpkgs"):
                if not re.search(rf'{name}\.url = "github:[^"]+/[0-9a-f]{{40}}(?:\?dir=nix)?";', flake):
                    raise ValueError(f"unpinned direct Nix input: {name}")
    return len(entries)


if __name__ == "__main__":
    try:
        print(f"template payloads and policy references: {validate()} ok (not a Nix build)")
    except (ValueError, KeyError, OSError) as error:
        print(f"template validation failed: {error}", file=sys.stderr)
        sys.exit(1)
