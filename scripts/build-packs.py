#!/usr/bin/env python3
"""Build the signed pack registry layout under packs/.

Reads pack sources from pack-sources/<namespace>/<name>/:

    pack.toml          version = "semver", description = "..."
    pack/profile.toml  a policy profile (optional)
    pack/group.toml    a policy group (optional)

For every source pack, emits packs/<namespace>/<name>/<version>/ with:

    manifest.json             the signed RegistryPackManifest (mvm schema v1)
    manifest.sigstore.json    detached cosign bundle over manifest.json
    files/<path>              the payload, byte-identical to the source

and regenerates packs/index.json (the registry index mvmctl search/pull
read). Refuses to overwrite an existing version with different bytes: pack
content is immutable once published, so a changed source needs a version
bump in its pack.toml.

The cosign bundle is produced by `cosign sign-blob` (keyless in the publish
workflow; a test key with COSIGN_KEY locally). The mvm client verifies the
bundle on every pull and on every policy load, against the publisher trust
policy.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "pack-sources"
PACKS = ROOT / "packs"

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.+-]+)?$")
COORD = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PUBLISHER_ISSUER = "https://token.actions.githubusercontent.com"
CURRENT_IDENTITY = "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
FORMER_IDENTITY = "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main"


def fail(message):
    sys.exit(f"pack build: {message}")


def parse_pack_toml(path):
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(path.read_text())
    version = data.get("version")
    description = data.get("description")
    if not isinstance(version, str) or not SEMVER.match(version):
        fail(f"{path}: version must be a strict semver string, got {version!r}")
    if not isinstance(description, str) or not description.strip():
        fail(f"{path}: description must be a non-empty string")
    if set(data) - {"version", "description", "image"}:
        fail(f"{path}: unknown pack metadata fields")
    image = data.get("image")
    if image is not None:
        if not isinstance(image, dict) or set(image) != {"manifest"}:
            fail(f"{path}: [image] must contain exactly manifest")
        manifest = image["manifest"]
        if not isinstance(manifest, str) or not manifest.startswith("pack/"):
            fail(f"{path}: image manifest must name an in-pack path")
    return {"version": version, "description": description, "image": image}


def sha256_of(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def manifest_bytes(reference, description, payload, image=None):
    # The payload root itself is the `pack/` directory: its contents ship
    # under `pack/` in the manifest, the path mvm reads policy documents
    # from (pack/profile.toml, pack/group.toml).
    files = []
    for path in payload.rglob("*"):
        if path.is_symlink():
            fail(f"payload symlink is not allowed: {path.relative_to(payload)}")
    for path in sorted(p for p in payload.rglob("*") if p.is_file()):
        rel = "pack/" + path.relative_to(payload).as_posix()
        parts = rel.split("/")
        if rel.startswith("/") or ".." in parts or not all(parts):
            fail(f"unsafe payload path {rel!r}")
        sha256, size = sha256_of(path)
        files.append({"path": rel, "sha256": sha256, "size": size})
    manifest = {
        "schema_version": 1,
        "reference": reference,
        "description": description,
        "files": files,
    }
    if image is not None:
        manifest_path = image["manifest"]
        parts = manifest_path.split("/")
        if (
            len(parts) < 3
            or parts[0] != "pack"
            or parts[-1] != "mvm.toml"
            or not all(parts)
            or ".." in parts
            or "\\" in manifest_path
        ):
            fail(f"unsafe image manifest path {manifest_path!r}")
        declared = {entry["path"] for entry in files}
        parent = "/".join(parts[:-1])
        for required in ("mvm.toml", "flake.nix", "flake.lock"):
            if f"{parent}/{required}" not in declared:
                fail(f"image source file {parent}/{required} is not signed")
        source_manifest = payload / "/".join(parts[1:])
        if source_manifest.stat().st_size > 64 * 1024:
            fail(f"image manifest {manifest_path!r} exceeds 64 KiB")
        try:
            source = tomllib.loads(source_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            fail(f"image manifest {manifest_path!r} is not valid UTF-8 TOML")
        if set(source) - {"schema_version", "flake", "profile", "name"}:
            fail(f"image manifest {manifest_path!r} declares host authority")
        if source.get("flake", ".") != ".":
            fail(f"image manifest {manifest_path!r} must select the local signed flake")
        manifest["image"] = image
    return json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n", files


def verify_bundle(manifest_path, bundle_path, identity):
    if not bundle_path.is_file():
        return False
    result = subprocess.run(
        [
            "cosign", "verify-blob", str(manifest_path),
            "--bundle", str(bundle_path),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", PUBLISHER_ISSUER,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def check_existing_payload(out, payload):
    published = out / "files" / "pack"
    if any(path.is_symlink() for path in (out / "files").rglob("*")):
        fail(f"{out}: published payload contains a symlink")
    source_files = {p.relative_to(payload) for p in payload.rglob("*") if p.is_file()}
    published_files = {p.relative_to(published) for p in published.rglob("*") if p.is_file()}
    if source_files != published_files:
        fail(f"{out}: published payload file set differs from source")
    for relative in source_files:
        if (payload / relative).read_bytes() != (published / relative).read_bytes():
            fail(f"{out}: published payload differs from source at {relative}")


def sign(manifest_path, bundle_path):
    cmd = ["cosign", "sign-blob", "--yes"]
    key = os.environ.get("COSIGN_KEY")
    if key:
        cmd += ["--key", key]
    cmd += ["--bundle", str(bundle_path), str(manifest_path)]
    subprocess.run(cmd, check=True)


def build_one(source):
    namespace, name = source.parent.name, source.name
    if not COORD.match(namespace) or not COORD.match(name):
        fail(f"{source}: namespace/name must match {COORD.pattern}")
    meta = parse_pack_toml(source / "pack.toml")
    payload = source / "pack"
    if not payload.is_dir():
        fail(f"{source}: missing pack/ payload directory")
    reference = f"{namespace}/{name}@{meta['version']}"
    out = PACKS / namespace / name / meta["version"]
    manifest, _ = manifest_bytes(reference, meta["description"], payload, meta["image"])

    if out.exists():
        existing = (out / "manifest.json").read_bytes()
        if existing != manifest:
            fail(
                f"{reference}: version already published with different bytes; "
                "bump the version in pack.toml"
            )
        check_existing_payload(out, payload)
        bundle = out / "manifest.sigstore.json"
        if verify_bundle(out / "manifest.json", bundle, CURRENT_IDENTITY):
            print(f"{reference}: unchanged")
            return
        if not verify_bundle(out / "manifest.json", bundle, FORMER_IDENTITY):
            fail(f"{reference}: existing signature is not trusted; refusing to re-sign")

    tmp = out.with_name(out.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    (tmp / "files").mkdir(parents=True)
    files_root = tmp / "files" / "pack"
    for path in payload.rglob("*"):
        if path.is_file():
            target = files_root / path.relative_to(payload)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    (tmp / "manifest.json").write_bytes(manifest)
    sign(tmp / "manifest.json", tmp / "manifest.sigstore.json")
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    print(f"{reference}: published")


def version_key(value):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", value)
    return [int(part) for part in match.groups()] if match else [0, 0, 0]


def rebuild_index():
    packs = []
    if PACKS.is_dir():
        for namespace in sorted(p for p in PACKS.iterdir() if p.is_dir()):
            for name in sorted(p for p in namespace.iterdir() if p.is_dir()):
                versions = sorted(
                    (
                        p.name
                        for p in name.iterdir()
                        if p.is_dir() and (p / "manifest.json").is_file()
                    ),
                    key=version_key,
                    reverse=True,
                )
                if versions:
                    manifest = json.loads(
                        (name / versions[0] / "manifest.json").read_text()
                    )
                    packs.append(
                        {
                            "namespace": namespace.name,
                            "name": name.name,
                            "description": manifest["description"],
                            "versions": versions,
                        }
                    )
    index = {"schema_version": 1, "packs": packs}
    PACKS.mkdir(exist_ok=True)
    (PACKS / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    print(f"index: {len(packs)} pack(s)")


def main():
    if not SOURCES.is_dir():
        fail("pack-sources/ does not exist")
    sources = sorted(
        p for p in SOURCES.glob("*/*") if p.is_dir() and (p / "pack.toml").is_file()
    )
    if not sources:
        fail("no pack sources under pack-sources/<namespace>/<name>/")
    for source in sources:
        build_one(source)
    rebuild_index()


if __name__ == "__main__":
    main()
