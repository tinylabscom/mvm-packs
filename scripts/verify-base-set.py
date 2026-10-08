#!/usr/bin/env python3
"""Check pre-downloaded base files against a pinned released MVM verifier.

This command does not fetch, build, sign, publish, or establish revocation
status. Its input directory remains caller-owned after the check.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import tempfile
from pathlib import Path


HEX64 = re.compile(r"^[0-9a-f]{64}$")
REPORT_FIELDS = {
    "verified", "scope", "set_version", "release_tag", "manifest_sha256",
    "signer_key_id", "unselected_artifacts_verified", "artifacts",
}
ARTIFACT_FIELDS = {"role", "target", "name", "sha256", "size"}


def refuse(reason):
    raise SystemExit(f"verify-base-set: {reason}")


def digest_and_size(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def require_regular(path, label):
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        refuse(f"{label} cannot be read: {error}")
    if not stat.S_ISREG(mode):
        refuse(f"{label} must be a regular file, not a link or special file")


def require_directory(path, label):
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        refuse(f"{label} cannot be read: {error}")
    if not stat.S_ISDIR(mode):
        refuse(f"{label} must be a directory, not a link")


def canonical_input(path, label, directory=False):
    if directory:
        require_directory(path, label)
    else:
        require_regular(path, label)
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        refuse(f"{label} cannot be resolved: {error}")


def source_image(pack_source):
    require_regular(pack_source, "pack source")
    if pack_source.name != "pack.toml":
        refuse("pack source must be named pack.toml")
    script = Path(__file__).with_name("build-packs.py")
    spec = importlib.util.spec_from_file_location("build_packs", script)
    if spec is None or spec.loader is None:
        refuse("pack descriptor validator is unavailable")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    namespace, name = pack_source.parent.parent.name, pack_source.parent.name
    if (pack_source.parent.parent.parent.name != "pack-sources"
            or not builder.COORD.fullmatch(namespace)
            or not builder.COORD.fullmatch(name)):
        refuse("pack source must be below pack-sources/namespace/name")
    try:
        metadata = builder.parse_pack_toml(pack_source)
    except (OSError, UnicodeError, ValueError) as error:
        refuse(f"pack source is invalid: {error}")
    image = metadata["image"]
    if image is None:
        refuse("pack source has no built-image descriptor")
    builder.validate_built_image_descriptor(
        image, f"{namespace}/{name}@{metadata['version']}"
    )
    return image


def expected_artifacts(platform):
    arch = platform.removeprefix("linux/")
    return {
        f"default-microvm-vmlinux-{arch}": "default_tenant_workload_kernel",
        f"default-microvm-rootfs-{arch}.ext4": "default_tenant_workload_rootfs",
        f"default-microvm-rootfs-{arch}.verity": "default_tenant_workload_rootfs",
        f"default-microvm-rootfs-{arch}.roothash": "default_tenant_workload_rootfs",
    }, arch


def check_inputs(mvmctl, expected_mvmctl_sha256, manifest, bundle, artifacts, expected):
    if not isinstance(expected_mvmctl_sha256, str) or not HEX64.fullmatch(expected_mvmctl_sha256):
        refuse("verifier SHA-256 pin must be 64 lowercase hex characters")
    for path, label in (
        (mvmctl, "verifier"), (manifest, "image-set manifest"),
        (bundle, "signature bundle"),
    ):
        require_regular(path, label)
    if manifest.name != "image-set.json" or bundle.name != "image-set.json.bundle":
        refuse("signed root files must retain their release asset names")
    if manifest == bundle:
        refuse("manifest and signature bundle must be distinct files")
    require_directory(artifacts, "artifact directory")
    actual = {entry.name for entry in artifacts.iterdir()}
    if actual != set(expected):
        refuse("artifact directory must contain exactly the selected base files")
    for name in expected:
        require_regular(artifacts / name, f"base artifact {name}")


def check_report(report, image, manifest, artifacts, expected, arch):
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        refuse("verifier JSON has missing or extra fields")
    if report["verified"] is not True or report["scope"] != "selected-artifacts":
        refuse("verifier did not affirm selected-artifact verification")
    if report["unselected_artifacts_verified"] is not False:
        refuse("verifier reported an unexpected verification scope")
    base = image["base_set"]
    manifest_sha256 = digest_and_size(manifest)[0]
    if manifest_sha256 != base["manifest_sha256"]:
        refuse("image-set manifest bytes differ from the source descriptor pin")
    if report["manifest_sha256"] != manifest_sha256:
        refuse("verifier reported a different signed root digest")
    if report["release_tag"] != base["release_tag"]:
        refuse("verifier reported a different signed release tag")
    if report["set_version"] != base["release_tag"].removeprefix("image-set/v"):
        refuse("verifier reported an inconsistent image-set version")
    if not isinstance(report["signer_key_id"], str) or not report["signer_key_id"]:
        refuse("verifier omitted the signing identity identifier")
    entries = report["artifacts"]
    if not isinstance(entries, list) or len(entries) != len(expected):
        refuse("verifier did not report exactly the selected base artifacts")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ARTIFACT_FIELDS:
            refuse("verifier artifact entry has missing or extra fields")
        name = entry["name"]
        if not isinstance(name, str) or name not in expected or name in seen:
            refuse("verifier reported an unexpected or duplicate artifact")
        seen.add(name)
        if entry["role"] != expected[name] or entry["target"] != arch:
            refuse(f"verifier reported the wrong role or architecture for {name}")
        sha256, size = digest_and_size(artifacts / name)
        if (not isinstance(entry["sha256"], str)
                or not HEX64.fullmatch(entry["sha256"])
                or entry["sha256"] != sha256
                or type(entry["size"]) is not int
                or entry["size"] != size
                or size == 0):
            refuse(f"verifier reported bytes that differ from staged artifact {name}")


def pin_verifier(binary, expected_sha256, private_directory):
    script = Path(__file__).with_name("reproduce-app-layer.py")
    spec = importlib.util.spec_from_file_location("reproduce_app_layer", script)
    if spec is None or spec.loader is None:
        refuse("executable pinning helper is unavailable")
    helper = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(helper)
    except (OSError, ImportError) as error:
        refuse(f"executable pinning helper is unavailable: {error}")
    try:
        return helper.pin_binary(binary, expected_sha256, private_directory)
    except (OSError, helper.ReproductionError) as error:
        refuse(f"verifier binary cannot be pinned: {error}")


def verify_base_set(pack_source, mvmctl, mvmctl_sha256, manifest, bundle, artifacts):
    pack_source, mvmctl, manifest, bundle, artifacts = map(
        Path, (pack_source, mvmctl, manifest, bundle, artifacts)
    )
    pack_source = canonical_input(pack_source, "pack source")
    mvmctl = canonical_input(mvmctl, "verifier")
    manifest = canonical_input(manifest, "image-set manifest")
    bundle = canonical_input(bundle, "signature bundle")
    artifacts = canonical_input(artifacts, "artifact directory", directory=True)
    image = source_image(pack_source)
    expected, arch = expected_artifacts(image["platform"])
    check_inputs(mvmctl, mvmctl_sha256, manifest, bundle, artifacts, expected)
    if digest_and_size(manifest)[0] != image["base_set"]["manifest_sha256"]:
        refuse("image-set manifest bytes differ from the source descriptor pin")
    with tempfile.TemporaryDirectory(prefix="mvm-base-verifier-") as private:
        pinned = pin_verifier(mvmctl, mvmctl_sha256, Path(private))
        command = [
            str(pinned), "image", "boot", "verify",
            "--manifest", str(manifest), "--bundle", str(bundle),
            "--artifacts", str(artifacts), "--require-complete", "--json",
        ]
        for name in sorted(expected):
            command.extend(("--artifact", name))
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=600
            )
        except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as error:
            refuse(f"verifier could not complete: {error}")
    if result.returncode != 0:
        refuse("signed image-set verifier refused the selected base files")
    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeError):
        refuse("verifier did not return one valid JSON report")
    check_report(report, image, manifest, artifacts, expected, arch)
    print(
        "Selected base files match the signed, lock-pinned verifier report. "
        "Unselected files and revocation status were not established."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvmctl", required=True, type=Path)
    parser.add_argument("--mvmctl-sha256", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    verify_base_set(
        args.pack_source, args.mvmctl, args.mvmctl_sha256,
        args.manifest, args.bundle, args.artifacts,
    )


if __name__ == "__main__":
    main()
