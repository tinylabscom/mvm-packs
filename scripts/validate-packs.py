#!/usr/bin/env python3
"""Validate packs/ against the RegistryPackManifest wire shape mvm parses.

Mirrors the serde contract in mvm-core (registry_pack.rs): deny unknown
fields, schema_version 1, canonical `namespace/name@x.y.z` reference with
strict semver, and files with relative safe paths, 64-hex SHA-256, and
non-negative sizes. Also checks every declared file exists with the exact
digest and length, and that a signature bundle sits beside each manifest.
"""

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from application_manifest import (
    COMPONENT_REFERENCE, COMPOSABLE_REFERENCE, unique_object, validate_application,
    validate_application_component, validate_composable_component, validate_layer_files,
)
from community_publishers import validate_directory
import pack_details
from community_index import validate_index as validate_community_index
from publisher_identity import (
    CURRENT_IDENTITY,
    PUBLISHER_ISSUER,
)

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = Path(__file__).resolve().parent
PACKS = ROOT / "packs"
REVOCATIONS = PACKS / "revocations.json"
REVOCATION_BUNDLE = PACKS / "revocations.sigstore.json"
PUBLISHER_IDENTITY = CURRENT_IDENTITY

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.+-]+)?$")
COORD = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

problems = []


# Policy-only versions published before binaries were required; immutable, never to grow.
LEGACY_POLICY_ONLY = frozenset({
    "agent/claude@1.0.1", "agent/codex@1.0.0", "agent/goose@1.0.0", "agent/opencode@1.0.0",
    "agent/pi@1.0.0", "runtime/go@1.0.0", "runtime/node@1.0.0", "runtime/python@1.0.0",
    "runtime/rust@1.0.0",
})


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


def verify_signature(path, reference):
    bundle = path.with_name("manifest.sigstore.json")
    if not bundle.is_file():
        problems.append(f"{path.relative_to(ROOT)}: missing signature bundle")
        return
    for identity in (PUBLISHER_IDENTITY,):
        command = [
            "cosign", "verify-blob", str(path), "--bundle", str(bundle),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", PUBLISHER_ISSUER,
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            problems.append("cosign is required for signature verification")
            return
        if result.returncode == 0:
            return
    problems.append(f"{path.relative_to(ROOT)}: publisher signature verification failed")


def validate_manifest(path, verify_signatures=False):
    rel = path.relative_to(ROOT).as_posix()
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        problems.append(f"{rel}: invalid JSON: {error}")
        return
    check(isinstance(manifest, dict), f"{rel}: manifest must be an object")
    if not isinstance(manifest, dict):
        return
    is_application = manifest.get("schema_version") == 2
    is_component = (type(manifest.get("schema_version")) is int
                    and manifest["schema_version"] == 3
                    and manifest.get("kind") == "application_component")
    is_composable = (type(manifest.get("schema_version")) is int
                     and manifest["schema_version"] == 4
                     and manifest.get("kind") in ("runtime_component", "tool_component"))
    if manifest.get("schema_version") == 3 and not is_component:
        problems.append(f"{rel}: unsupported schema-3 pack kind; runtime layers remain unpublishable")
    if manifest.get("schema_version") == 4 and not is_composable:
        problems.append(f"{rel}: unsupported schema-4 pack kind")
    fields = {"schema_version", "reference", "description", "files"}
    if is_application:
        fields = {"schema_version", "kind", "reference", "description", "application"}
    elif is_component:
        fields = {"schema_version", "kind", "reference", "description", "application_component", "files"}
    elif is_composable:
        fields = {"schema_version", "kind", "reference", "description", manifest["kind"], "files"}
    check(
        set(manifest) == fields,
        f"{rel}: unknown or missing fields: {sorted(manifest)}",
    )
    check(
        type(manifest.get("schema_version")) is int
        and manifest["schema_version"] in (1, 2, 3, 4),
        f"{rel}: schema_version must be integer 1, 2, 3 or 4",
    )
    if not is_application and not is_component and not is_composable:
        check(
            manifest.get("reference") in LEGACY_POLICY_ONLY,
            f"{rel}: a pack must embed its application binary; policy-only manifests are legacy",
        )
    if is_application:
        check(manifest.get("kind") == "application", f"{rel}: kind must be application")
        try:
            validate_application(manifest.get("application"))
        except ValueError as error:
            problems.append(f"{rel}: {error}")
    if is_component:
        check(manifest.get("kind") == "application_component",
              f"{rel}: kind must be application_component")
        check(len(raw) <= 1 << 20, f"{rel}: application component descriptor exceeds 1 MiB")
        try:
            validate_application_component(manifest.get("application_component"))
            validate_layer_files(manifest.get("files"))
        except ValueError as error:
            problems.append(f"{rel}: {error}")
        check(isinstance(manifest.get("reference"), str)
              and COMPONENT_REFERENCE.fullmatch(manifest["reference"]) is not None,
              f"{rel}: application component reference must be exact ns/name@major.minor.patch")
    if is_composable:
        kind = manifest["kind"]
        check(len(raw) <= 1 << 20, f"{rel}: {kind} descriptor exceeds 1 MiB")
        try:
            validate_composable_component(manifest.get(kind), kind, manifest.get("reference"))
            validate_layer_files(manifest.get("files"))
        except ValueError as error:
            problems.append(f"{rel}: {error}")
        component_reference = manifest.get("reference")
        check(isinstance(component_reference, str)
              and COMPOSABLE_REFERENCE.fullmatch(component_reference) is not None
              and component_reference.split("/", 1)[0] == kind.removesuffix("_component"),
              f"{rel}: {kind} reference must be exact {kind.removesuffix('_component')}/name@major.minor.patch")

    reference = manifest.get("reference", "")
    parts = re.fullmatch(r"([^/@]+)/([^/@]+)@([^/@]+)", reference) if isinstance(reference, str) else None
    check(parts is not None, f"{rel}: reference {reference!r} must be ns/name@version")
    if parts:
        namespace, name, version = parts.groups()
        check(COORD.fullmatch(namespace), f"{rel}: bad namespace {namespace!r}")
        check(COORD.fullmatch(name), f"{rel}: bad name {name!r}")
        check(
            SEMVER.fullmatch(version) and version == version.split("+")[0],
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

    files = [] if is_application else manifest.get("files")
    if not is_application:
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
        if not isinstance(rel_path, str):
            problems.append(f"{rel}: unsafe file path {rel_path!r}")
            continue
        parts_p = rel_path.split("/")
        if (not rel_path or rel_path.startswith("/") or ".." in parts_p
                or not all(parts_p) or "\\" in rel_path):
            problems.append(f"{rel}: unsafe file path {rel_path!r}")
            continue
        check(rel_path not in seen, f"{rel}: duplicate file path {rel_path!r}")
        seen.add(rel_path)
        digest_valid = isinstance(entry.get("sha256"), str) and HEX64.fullmatch(entry["sha256"])
        check(digest_valid, f"{rel}: sha256 for {rel_path!r} must be 64 lowercase hex")
        size = entry.get("size")
        size_valid = type(size) is int and size >= 0
        check(size_valid, f"{rel}: bad size for {rel_path!r}")

        on_disk = path.parent / "files" / rel_path
        check(on_disk.is_file(), f"{rel}: declared file {rel_path!r} is missing")
        if on_disk.is_file() and digest_valid and size_valid:
            digest, actual_size = sha256_and_size(on_disk)
            check(
                digest == entry["sha256"] and actual_size == size,
                f"{rel}: {rel_path!r} digest/size drift from the manifest",
            )

    signature_trusted = True
    if verify_signatures:
        previous_problems = len(problems)
        verify_signature(path, reference)
        signature_trusted = len(problems) == previous_problems

    check(
        path.with_name("manifest.sigstore.json").is_file(),
        f"{rel}: missing manifest.sigstore.json",
    )
    declared = {Path("files") / entry["path"] for entry in files if isinstance(entry, dict) and isinstance(entry.get("path"), str)} if isinstance(files, list) else set()
    allowed = declared | {Path("manifest.json"), Path("manifest.sigstore.json")}
    if is_component or is_composable:
        allowed |= {parent for item in declared for parent in item.parents if parent != Path(".")}
    for included in path.parent.rglob("*"):
        relative = included.relative_to(path.parent)
        if included.is_symlink():
            problems.append(f"{rel}: symlink is not allowed: {relative}")
        elif (is_application or is_component or is_composable) and relative not in allowed:
            problems.append(f"{rel}: application payload is not allowed: {relative}")
        elif included.is_file() and relative not in allowed:
            problems.append(f"{rel}: unsigned file is not allowed: {relative}")


def validate_index():
    """The sole root catalog must pin the exact published manifest bytes."""
    builder = runpy.run_path(str(SCRIPTS / "build-packs.py"))
    try:
        expected = builder["registry_index"](PACKS)
    except (OSError, ValueError, KeyError, TypeError) as error:
        problems.append(f"cannot derive pack index from manifests: {error}")
        return
    check(
        not (PACKS / "index.json").exists(),
        "packs/index.json: obsolete duplicate catalog must be removed",
    )
    try:
        index = json.loads((ROOT / "index.json").read_text())
    except (OSError, ValueError) as error:
        problems.append(f"index.json: cannot read pack index: {error}")
        return
    check(
        isinstance(index, dict)
        and type(index.get("schema_version")) is int
        and index == expected,
        "index.json: must exactly match published manifests and their SHA-256 pins "
        "(run python3 scripts/build-packs.py to regenerate)",
    )


def validate_details():
    """Recorded archive details must be well formed and match the signed descriptor they describe."""
    directory = ROOT / "pack-details"
    if not directory.is_dir():
        return
    for path in sorted(directory.rglob("*")):
        rel = path.relative_to(ROOT).as_posix()
        if path.is_dir():
            continue
        parts = path.relative_to(directory).parts
        if path.is_symlink() or len(parts) != 3 or path.suffix != ".json":
            problems.append(f"{rel}: not a recorded-details file (expected <ns>/<name>/<version>.json)")
            continue
        namespace, name, version = parts[0], parts[1], path.stem
        try:
            details = pack_details.validate(json.loads(path.read_text(encoding="utf-8"),
                                                       object_pairs_hook=unique_object))
            manifest = json.loads((PACKS / namespace / name / version / "manifest.json").read_text(),
                                  object_pairs_hook=unique_object)
            bundle = manifest["application"]["bundle"]
            if (details["reference"] != f"{namespace}/{name}@{version}"
                    or details["archive"]["sha256"] != bundle["archive_sha256"]
                    or details["archive"]["size"] != bundle["archive_size"]
                    or details["archive"]["key_id"] != bundle["key_id"]):
                raise ValueError("does not match the signed descriptor")
        except (OSError, ValueError, KeyError, TypeError) as error:
            problems.append(f"{rel}: {error}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-signatures", action="store_true", help="verify every bundle against the publisher identity")
    parser.add_argument("--require-revocations", action="store_true", help="require a current signed revocation feed")
    args = parser.parse_args(argv)
    if args.require_revocations and not args.verify_signatures:
        parser.error("--require-revocations requires --verify-signatures")
    problems.clear()
    if not PACKS.is_dir():
        sys.exit("validate-packs: packs/ does not exist")
    manifests = sorted(PACKS.glob("*/*/*/manifest.json"))
    check(bool(manifests), "no manifests under packs/<ns>/<name>/<version>/")
    for manifest in manifests:
        validate_manifest(manifest, args.verify_signatures)
    validate_index()
    problems.extend(validate_directory(ROOT / "community" / "publishers"))
    validate_details()
    community_index = ROOT / "community" / "index.json"
    if community_index.is_file():
        try:
            validate_community_index(json.loads(community_index.read_text(encoding="utf-8"),
                                                object_pairs_hook=unique_object))
        except (OSError, ValueError) as error:
            problems.append(f"community/index.json: {error}")
    if args.require_revocations or REVOCATIONS.exists() or REVOCATION_BUNDLE.exists():
        if (not REVOCATIONS.is_file() or not REVOCATION_BUNDLE.is_file()
                or REVOCATIONS.is_symlink() or REVOCATION_BUNDLE.is_symlink()):
            problems.append("revocation document or signature bundle is missing")
        else:
            revocations = runpy.run_path(str(ROOT / "scripts" / "build-revocations.py"))
            try:
                revocations["parse_document"](REVOCATIONS.read_bytes(), datetime.now(timezone.utc))
                if args.verify_signatures:
                    revocations["verify_bundle"](REVOCATIONS, REVOCATION_BUNDLE)
            except (OSError, revocations["RevocationError"]) as error:
                problems.append(f"revocations.json: {error}")
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        sys.exit(1)
    print(f"validate-packs: {len(manifests)} manifest(s) ok")


if __name__ == "__main__":
    main()
