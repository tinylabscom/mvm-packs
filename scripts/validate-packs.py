#!/usr/bin/env python3
"""Validate packs/ against the RegistryPackManifest wire shape mvm parses.

Mirrors the serde contract in mvm-core (registry_pack.rs): deny unknown
fields, schema_version 1, canonical `namespace/name@x.y.z` reference with
strict semver, and files with relative safe paths, 64-hex SHA-256, and
non-negative sizes. Also checks every declared file exists with the exact
digest and length, and that a signature bundle sits beside each manifest.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKS = ROOT / "packs"

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.+-]+)?$")
COORD = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

problems = []


def check(condition, message):
    if not condition:
        problems.append(message)


def sha256_and_size(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def validate_manifest(path):
    rel = path.relative_to(ROOT).as_posix()
    try:
        manifest = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        problems.append(f"{rel}: invalid JSON: {error}")
        return
    check(isinstance(manifest, dict), f"{rel}: manifest must be an object")
    check(
        set(manifest) == {"schema_version", "reference", "description", "files"},
        f"{rel}: unknown or missing fields: {sorted(manifest)}",
    )
    check(manifest.get("schema_version") == 1, f"{rel}: schema_version must be 1")

    reference = manifest.get("reference", "")
    parts = re.match(r"^([^/@]+)/([^/@]+)@([^/@]+)$", reference or "")
    check(parts is not None, f"{rel}: reference {reference!r} must be ns/name@version")
    if parts:
        namespace, name, version = parts.groups()
        check(COORD.match(namespace), f"{rel}: bad namespace {namespace!r}")
        check(COORD.match(name), f"{rel}: bad name {name!r}")
        check(
            SEMVER.match(version) and version == version.split("+")[0],
            f"{rel}: version {version!r} must be strict semver",
        )
        check(
            path.parent == PACKS / namespace / name / version,
            f"{rel}: reference does not match its directory",
        )

    description = manifest.get("description")
    check(
        isinstance(description, str) and description.strip(),
        f"{rel}: description must be a non-empty string",
    )

    files = manifest.get("files")
    check(isinstance(files, list), f"{rel}: files must be a list")
    seen = set()
    for entry in files if isinstance(files, list) else []:
        check(
            isinstance(entry, dict) and set(entry) == {"path", "sha256", "size"},
            f"{rel}: file entry must have exactly path/sha256/size: {entry!r}",
        )
        if not isinstance(entry, dict):
            continue
        rel_path = entry.get("path", "")
        parts_p = rel_path.split("/")
        check(
            isinstance(rel_path, str)
            and rel_path
            and not rel_path.startswith("/")
            and ".." not in parts_p
            and all(parts_p)
            and "\\" not in rel_path,
            f"{rel}: unsafe file path {rel_path!r}",
        )
        check(rel_path not in seen, f"{rel}: duplicate file path {rel_path!r}")
        seen.add(rel_path)
        check(
            HEX64.match(entry.get("sha256", "")),
            f"{rel}: sha256 for {rel_path!r} must be 64 lowercase hex",
        )
        size = entry.get("size")
        check(isinstance(size, int) and size >= 0, f"{rel}: bad size for {rel_path!r}")

        on_disk = path.parent / "files" / rel_path
        check(on_disk.is_file(), f"{rel}: declared file {rel_path!r} is missing")
        if on_disk.is_file():
            digest, actual_size = sha256_and_size(on_disk)
            check(
                digest == entry["sha256"] and actual_size == size,
                f"{rel}: {rel_path!r} digest/size drift from the manifest",
            )

    check(
        path.with_name("manifest.sigstore.json").is_file(),
        f"{rel}: missing manifest.sigstore.json",
    )


def main():
    if not PACKS.is_dir():
        sys.exit("validate-packs: packs/ does not exist")
    manifests = sorted(PACKS.glob("*/*/*/manifest.json"))
    check(bool(manifests), "no manifests under packs/<ns>/<name>/<version>/")
    for manifest in manifests:
        validate_manifest(manifest)
    index = json.loads((PACKS / "index.json").read_text())
    check(set(index) == {"schema_version", "packs"}, "index.json: unexpected fields")
    check(index.get("schema_version") == 1, "index.json: schema_version must be 1")
    for entry in index.get("packs", []):
        check(set(entry) == {"namespace", "name", "description", "versions"}, "index.json: bad entry")
        for version in entry.get("versions", []):
            check(
                (PACKS / entry["namespace"] / entry["name"] / version / "manifest.json").is_file(),
                f"index.json: {entry['namespace']}/{entry['name']}@{version} not on disk",
            )
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        sys.exit(1)
    print(f"validate-packs: {len(manifests)} manifest(s) ok")


if __name__ == "__main__":
    main()
