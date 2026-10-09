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

from publisher_identity import (
    CURRENT_IDENTITY,
    FORMER_IDENTITY,
    PUBLISHER_ISSUER,
    accepts_former,
    is_historical_manifest,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "pack-sources"
PACKS = ROOT / "packs"

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.+-]+)?$")
COORD = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_SET_TAG = re.compile(r"image-set/v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
BUILT_IMAGE_ASSETS = {
    "rootfs": "rootfs.ext4",
    "verity": "rootfs.verity",
    "roothash": "rootfs.roothash",
    "mvm_meta": "mvm-meta.json",
    "rootfs_signature_bundle": "rootfs.signature.json",
    "provenance_statement": "provenance.json",
    "provenance_signature_bundle": "provenance.signature.json",
}


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
    if set(data) - {"version", "description", "image", "image_build"}:
        fail(f"{path}: unknown pack metadata fields")
    image = data.get("image")
    if image is not None and not isinstance(image, dict):
        fail(f"{path}: [image] must be a table")
    image_build = data.get("image_build")
    if image_build is not None:
        validate_image_build_intent(image_build, f"{path.parent.parent.name}/{path.parent.name}@{version}")
    if image is not None and image_build is not None:
        fail(f"{path}: [image] and [image_build] cannot both be present")
    return {"version": version, "description": description, "image": image,
            "image_build": image_build}


def validate_image_build_intent(intent, reference):
    """Validate pre-build inputs without claiming digests for future outputs."""
    if not isinstance(intent, dict) or set(intent) != {
        "schema_version", "platform", "base_set", "release"
    } or type(intent["schema_version"]) is not int or intent["schema_version"] != 1:
        fail(f"{reference}: image build intent has missing, extra or unsupported fields")
    if intent["platform"] not in ("linux/x86_64", "linux/aarch64"):
        fail(f"{reference}: image build platform is unsupported")
    base = intent["base_set"]
    if not isinstance(base, dict) or set(base) != {
        "repository", "release_tag", "manifest_sha256"
    } or base["repository"] != "tinylabscom/mvm-images":
        fail(f"{reference}: image build base set is invalid")
    tag = base["release_tag"]
    if not isinstance(tag, str) or not IMAGE_SET_TAG.fullmatch(tag):
        fail(f"{reference}: image build base release tag is invalid")
    if not isinstance(base["manifest_sha256"], str) or not HEX64.fullmatch(base["manifest_sha256"]):
        fail(f"{reference}: image build base root digest is invalid")
    namespace_name, version = reference.split("@", 1)
    expected_tag = f"pack-{namespace_name.replace('/', '-')}-v{version}"
    if intent["release"] != {"repository": "tinylabscom/mvm-packs", "tag": expected_tag}:
        fail(f"{reference}: image build release identity is invalid")


def validate_built_image_descriptor(image, reference):
    """Validate source metadata only; no image asset is fetched or trusted here."""
    if not isinstance(image, dict) or image.get("schema_version") != 2:
        fail(
            f"{reference}: source-only image is not publishable: schema v1 has no "
            "built image digest, base-set pin, or provenance attestation"
        )
    if set(image) != {"schema_version", "platform", "base_set", "release", "assets"}:
        fail(f"{reference}: built image descriptor has missing or extra fields")
    if image["platform"] not in ("linux/x86_64", "linux/aarch64"):
        fail(f"{reference}: built image platform is unsupported")

    base = image["base_set"]
    if not isinstance(base, dict) or set(base) != {
        "repository", "release_tag", "manifest_sha256"
    }:
        fail(f"{reference}: base_set must name repository, release_tag, and manifest_sha256")
    if base["repository"] != "tinylabscom/mvm-images":
        fail(f"{reference}: base_set repository is not the MVM image-set repository")
    tag = base["release_tag"]
    if not isinstance(tag, str) or not IMAGE_SET_TAG.fullmatch(tag):
        fail(f"{reference}: base_set release_tag must be an immutable image-set version")
    if not isinstance(base["manifest_sha256"], str) or not HEX64.fullmatch(base["manifest_sha256"]):
        fail(f"{reference}: base_set manifest_sha256 must be lowercase SHA-256")

    release = image["release"]
    if not isinstance(release, dict) or set(release) != {"repository", "tag"}:
        fail(f"{reference}: release must name repository and tag")
    namespace_name, version = reference.split("@", 1)
    expected_tag = f"pack-{namespace_name.replace('/', '-')}-v{version}"
    if release != {"repository": "tinylabscom/mvm-packs", "tag": expected_tag}:
        fail(f"{reference}: release repository or tag does not match {expected_tag}")

    assets = image["assets"]
    if not isinstance(assets, dict) or set(assets) != set(BUILT_IMAGE_ASSETS):
        fail(f"{reference}: assets must name every built image and attestation asset")
    for role, expected_name in BUILT_IMAGE_ASSETS.items():
        asset = assets[role]
        if not isinstance(asset, dict) or set(asset) != {"name", "sha256", "size"}:
            fail(f"{reference}: {role} asset must have exactly name, sha256, and size")
        if asset["name"] != expected_name:
            fail(f"{reference}: {role} asset name must be {expected_name}")
        if not isinstance(asset["sha256"], str) or not HEX64.fullmatch(asset["sha256"]):
            fail(f"{reference}: {role} sha256 must be lowercase SHA-256")
        if type(asset["size"]) is not int or asset["size"] <= 0:
            fail(f"{reference}: {role} size must be a positive integer")


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
    reference = f"{namespace}/{name}@{meta['version']}"
    if meta["image_build"] is not None:
        fail(f"{reference}: image build intent is not publishable without signed release assets")
    if meta["image"] is not None:
        validate_built_image_descriptor(meta["image"], reference)
        fail(f"{reference}: built image packs are not publishable until consumer verification is available")
    payload = source / "pack"
    if not payload.is_dir():
        fail(f"{source}: missing pack/ payload directory")
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
        if not is_historical_manifest(reference, existing) or not verify_bundle(
            out / "manifest.json", bundle, FORMER_IDENTITY
        ):
            fail(f"{reference}: existing signature is not trusted; refusing to re-sign")
        if accepts_former(reference, existing):
            print(f"{reference}: unchanged")
            return

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
