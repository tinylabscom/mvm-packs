#!/usr/bin/env python3
"""Resolve community references into community/index.json (ADR 002, docs/community-index.md).

For every community/publishers/<owner>.toml, find the author's GitHub releases,
download each pack's signed manifest and bundle, verify the signature against the
exact identity in the reference, validate the descriptor, and copy the two small
files verbatim under community/packs/. This script never signs anything.

Scope: application descriptors only. Policy packs need a payload convention and
are skipped with a message. The reference's `environment` is recorded but not
checked: cosign's certificate identity does not carry it.
"""

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from application_manifest import unique_object, validate_application  # noqa: E402
from community_index import VERSION, validate_index  # noqa: E402
from community_publishers import validate_directory, validate_reference  # noqa: E402

ROOT = SCRIPTS.parent
ISSUER = "https://token.actions.githubusercontent.com"
MAX_METADATA = 1 << 20
MANIFEST, BUNDLE = "manifest.json", "manifest.sigstore.json"


def identity(publisher):
    return f"https://github.com/{publisher['repository']}/{publisher['workflow']}@{publisher['ref']}"


def asset_names(name):
    return f"{name}.{MANIFEST}", f"{name}.{BUNDLE}"


def version_key(version):
    return [int(part) for part in version.split("-", 1)[0].split(".")]


def check_manifest(owner, name, raw):
    """Return (version, descriptor) for a valid application manifest, else raise ValueError."""
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version", "kind", "reference", "description", "application"}:
        raise ValueError("only application descriptors are supported (schema 2, kind application)")
    if manifest["schema_version"] != 2 or manifest["kind"] != "application":
        raise ValueError("only application descriptors are supported (schema 2, kind application)")
    match = re.fullmatch(rf"{re.escape(owner)}/{re.escape(name)}@(.+)", str(manifest["reference"]))
    if not match or not VERSION.fullmatch(match.group(1)):
        raise ValueError(f"reference must be {owner}/{name}@<semver>")
    if not isinstance(manifest["description"], str):
        raise ValueError("description must be text")
    validate_application(manifest["application"])
    return match.group(1), manifest


def resolve(root, list_releases, fetch, verify, read_back):
    """Update root/community from the references; return a list of report lines."""
    community = root / "community"
    report = []
    problems = validate_directory(community / "publishers")
    if problems:
        return [f"reference error: {p}" for p in problems]
    packs = []
    for path in sorted((community / "publishers").glob("*.toml")) if (community / "publishers").is_dir() else []:
        owner = path.stem
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        validate_reference(owner, data)
        publisher = {k: data[k] for k in ("repository", "workflow", "ref")} | {"environment": data.get("environment", "")}
        for name in data["packs"]:
            versions = {}
            # Keep versions already mirrored, re-verified against the current reference.
            mirror = community / "packs" / owner / name
            for existing in sorted(mirror.glob("*/" + MANIFEST)) if mirror.is_dir() else []:
                raw = existing.read_bytes()
                bundle = existing.with_name(BUNDLE)
                try:
                    version, manifest = check_manifest(owner, name, raw)
                    if existing.parent.name != version or not verify(existing, bundle, identity(publisher)):
                        raise ValueError("signature or version no longer matches the reference")
                except (ValueError, OSError) as error:
                    report.append(f"{owner}/{name}@{existing.parent.name}: delisted: {error}")
                    continue
                versions[version] = (hashlib.sha256(raw).hexdigest(), manifest)
            # Add new verified releases.
            m_name, b_name = asset_names(name)
            for release in list_releases(publisher["repository"]):
                if release.get("draft") or release.get("prerelease"):
                    continue
                assets = {a["name"]: a for a in release.get("assets", [])}
                if m_name not in assets or b_name not in assets:
                    continue
                prefix = f"https://github.com/{publisher['repository']}/releases/download/"
                if not all(assets[n]["browser_download_url"].startswith(prefix) for n in (m_name, b_name)):
                    report.append(f"{owner}/{name}: {release.get('tag_name')}: asset URL is outside the repository")
                    continue
                try:
                    raw, bundle_raw = (fetch(assets[n]["browser_download_url"]) for n in (m_name, b_name))
                    version, manifest = check_manifest(owner, name, raw)
                    digest = hashlib.sha256(raw).hexdigest()
                    if version in versions:
                        if versions[version][0] != digest:
                            report.append(f"{owner}/{name}@{version}: REFUSED: released bytes differ from the listed version")
                        continue
                    with tempfile.TemporaryDirectory() as scratch:
                        staged = Path(scratch)
                        (staged / MANIFEST).write_bytes(raw)
                        (staged / BUNDLE).write_bytes(bundle_raw)
                        if not verify(staged / MANIFEST, staged / BUNDLE, identity(publisher)):
                            raise ValueError("signature does not match the reference identity")
                    read_back(manifest["application"])
                    target = mirror / version
                    target.mkdir(parents=True, exist_ok=True)
                    (target / MANIFEST).write_bytes(raw)
                    (target / BUNDLE).write_bytes(bundle_raw)
                except (ValueError, OSError) as error:
                    report.append(f"{owner}/{name}: {release.get('tag_name')}: skipped: {error}")
                    continue
                versions[version] = (digest, manifest)
                report.append(f"{owner}/{name}@{version}: listed")
            if not versions:
                continue
            ordered = sorted(versions, key=version_key, reverse=True)
            entries = []
            for version in ordered:
                app = versions[version][1]["application"]
                entry = {"version": version, "manifest_sha256": versions[version][0],
                         "guest_arch": app["guest_arch"], "size_bytes": app["bundle"]["archive_size"]}
                if version == ordered[0]:
                    entry["tags"] = ["latest"]
                entries.append(entry)
            description = versions[ordered[0]][1]["description"]
            packs.append({"namespace": owner, "name": name, "description": description,
                          "publisher": publisher, "versions": entries})
    packs.sort(key=lambda p: (p["namespace"], p["name"]))
    index = validate_index({"schema_version": 3, "kind": "community", "packs": packs})
    community.mkdir(exist_ok=True)
    (community / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return report


def github_releases(repository):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/releases?per_page=30",
        headers={"Accept": "application/vnd.github+json", **(
            {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get("GITHUB_TOKEN") else {})})
    limit = 32 << 20
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{repository}: release list is larger than {limit} bytes")
    return json.loads(data)


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError(f"{url}: metadata file is larger than {MAX_METADATA} bytes")
    return data


def cosign_verify(manifest, bundle, expected_identity):
    return subprocess.run(
        ["cosign", "verify-blob", str(manifest), "--bundle", str(bundle),
         "--certificate-identity", expected_identity, "--certificate-oidc-issuer", ISSUER],
        capture_output=True, check=False).returncode == 0


def archive_read_back(application):
    builder = runpy.run_path(str(SCRIPTS / "build-packs.py"))
    try:
        builder["verify_archive"](application)
    except SystemExit as error:
        raise ValueError(str(error)) from error


def main(argv=None, root=ROOT):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    for line in resolve(root, github_releases, fetch, cosign_verify, archive_read_back):
        print(line)


if __name__ == "__main__":
    main()
