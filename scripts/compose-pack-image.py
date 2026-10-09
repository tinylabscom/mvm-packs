#!/usr/bin/env python3
"""Reproduce an unsigned rootfs composed from a verified pinned base and app layer.

Run inside the project builder VM. This command does not sign or publish a pack.
"""

import argparse
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath


OUTPUTS = frozenset(("rootfs.ext4", "rootfs.verity", "rootfs.roothash", "asset-report.json"))
INPUTS = frozenset((
    "candidate.json", "pack.toml", "image-set.json", "image-set.json.bundle", "base", "layer"
))


class CompositionError(Exception):
    """A composed image cannot be trusted as a reproducible candidate."""


def load_helper(filename, module_name):
    spec = importlib.util.spec_from_file_location(module_name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise CompositionError(f"{filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def regular(path, label):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise CompositionError(f"{label} must be a regular file, not a link")


def directory(path, label):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise CompositionError(f"{label} must be a directory, not a link")


def check_record(record, path, reproducer, label):
    if not isinstance(record, dict) or set(record) != {"sha256", "size"}:
        raise CompositionError(f"{label} has an invalid digest record")
    try:
        actual = reproducer.digest_file(path)
    except reproducer.ReproductionError as error:
        raise CompositionError(f"{label} cannot be read as a regular file") from error
    if (record["sha256"], record["size"]) != actual or actual[1] <= 0:
        raise CompositionError(f"{label} differs from the candidate digest record")


def staged_pack_source(candidate, reference, private, binder):
    builder = load_helper("build-packs.py", "build_packs_composer")
    coordinates, separator, version = reference.partition("@")
    parts = coordinates.split("/")
    if (separator != "@" or len(parts) != 2
            or not all(builder.COORD.fullmatch(part) for part in parts)
            or not builder.SEMVER.fullmatch(version)):
        raise CompositionError("reference must be a versioned namespace/name@version")
    source = private / "pack-sources" / parts[0] / parts[1]
    source.mkdir(parents=True, mode=0o700)
    try:
        binder.copy_regular(candidate / "pack.toml", source / "pack.toml")
    except binder.CandidateError as error:
        raise CompositionError("pack source cannot be staged safely") from error
    metadata = builder.parse_pack_toml(source / "pack.toml")
    if metadata["version"] != version:
        raise CompositionError("pack source version differs from the requested reference")
    return source / "pack.toml"


def check_candidate(candidate, pack_source, mvmctl, mvmctl_sha256, base, reproducer):
    """Re-read the candidate bytes; its unsigned report is never a trust anchor."""
    directory(candidate, "candidate")
    if {entry.name for entry in candidate.iterdir()} != INPUTS:
        raise CompositionError("candidate has missing or extra entries")
    for name in ("candidate.json", "pack.toml", "image-set.json", "image-set.json.bundle"):
        regular(candidate / name, name)
    directory(candidate / "base", "candidate base")
    directory(candidate / "layer", "candidate layer")
    report = json.loads(
        (candidate / "candidate.json").read_bytes(), object_pairs_hook=reproducer.unique_object
    )
    fields = {
        "schema_version", "kind", "platform", "pack_source", "base_set",
        "signed_root_manifest", "signed_root_bundle", "verifier_sha256",
        "verification_scope", "base_artifacts", "application_layer",
    }
    if (not isinstance(report, dict) or set(report) != fields
            or report["schema_version"] != 1
            or report["kind"] != "unsigned-image-candidate"
            or report["verification_scope"] != "selected-base-artifacts-only"
            or report["verifier_sha256"] != mvmctl_sha256):
        raise CompositionError("candidate report has an unsupported shape or verifier")
    image = base.source_image(pack_source)
    if report["platform"] != image["platform"] or report["base_set"] != image["base_set"]:
        raise CompositionError("candidate image identity differs from the pack source")
    expected, _ = base.expected_artifacts(image["platform"])
    if ({entry.name for entry in (candidate / "base").iterdir()} != set(expected)
            or not isinstance(report["base_artifacts"], dict)
            or set(report["base_artifacts"]) != set(expected)):
        raise CompositionError("candidate base files differ from the selected set")
    for name, record, path in (
        ("pack source", report["pack_source"], candidate / "pack.toml"),
        ("signed root manifest", report["signed_root_manifest"], candidate / "image-set.json"),
        ("signed root bundle", report["signed_root_bundle"], candidate / "image-set.json.bundle"),
    ):
        check_record(record, path, reproducer, name)
    for name in sorted(expected):
        check_record(
            report["base_artifacts"][name], candidate / "base" / name,
            reproducer, f"base artifact {name}",
        )
    try:
        layer_records = reproducer.verify_output(candidate / "layer")
    except reproducer.ReproductionError as error:
        raise CompositionError("application layer cannot be verified") from error
    if (not isinstance(report["application_layer"], dict)
            or report["application_layer"] != {
                name: {"sha256": digest, "size": size}
                for name, (digest, size) in layer_records.items()
            }):
        raise CompositionError("application layer differs from the candidate report")
    base.verify_base_set(
        pack_source, mvmctl, mvmctl_sha256,
        candidate / "image-set.json", candidate / "image-set.json.bundle",
        candidate / "base",
    )
    rootfs_name = f"default-microvm-rootfs-{image['platform'].removeprefix('linux/')}.ext4"
    return report, rootfs_name


def snapshot_candidate(source, destination, binder):
    """Pin caller-owned inputs through no-follow descriptors before checking."""
    directory(source, "candidate")
    if {entry.name for entry in source.iterdir()} != INPUTS:
        raise CompositionError("candidate has missing or extra entries")
    destination.mkdir(mode=0o700)
    try:
        for name in sorted(INPUTS - {"base", "layer"}):
            binder.copy_regular(source / name, destination / name)
        for folder in ("base", "layer"):
            original = source / folder
            directory(original, f"candidate {folder}")
            copy = destination / folder
            copy.mkdir(mode=0o700)
            for entry in original.iterdir():
                binder.copy_regular(entry, copy / entry.name)
    except binder.CandidateError as error:
        raise CompositionError("candidate cannot be snapshotted safely") from error


def checked_link_target(source, target, root):
    """Validate a guest symlink lexically; never resolve it on the host."""
    link = os.readlink(source)
    parts = [] if link.startswith("/") else list(target.parent.relative_to(root).parts)
    for component in PurePosixPath(link).parts:
        if component in ("", "/", "."):
            continue
        if component == "..":
            if not parts:
                raise CompositionError(f"application symlink target escapes guest root: {source}")
            parts.pop()
        else:
            parts.append(component)
    if link.startswith("/") and parts[:2] != ["nix", "store"]:
        raise CompositionError(f"application symlink target is not in the guest Nix store: {source}")
    return link


def merge_additive(application, destination, root=None):
    """Add application entries without replacing any base entry or following links."""
    directory(application, "application tree")
    directory(destination, "base tree")
    if root is None:
        root = destination
    original_mode = stat.S_IMODE(destination.lstat().st_mode)
    destination.chmod(original_mode | stat.S_IWUSR)
    try:
        for source in sorted(application.iterdir()):
            target = destination / source.name
            mode = source.lstat().st_mode
            if stat.S_ISDIR(mode):
                if target.exists() or target.is_symlink():
                    if not stat.S_ISDIR(target.lstat().st_mode):
                        raise CompositionError(f"application directory collides with base: {source.name}")
                else:
                    target.mkdir(mode=stat.S_IMODE(mode))
                merge_additive(source, target, root)
            elif stat.S_ISREG(mode):
                if target.exists() or target.is_symlink():
                    raise CompositionError(f"application file collides with base: {source.name}")
                shutil.copy2(source, target, follow_symlinks=False)
            elif stat.S_ISLNK(mode):
                if target.exists() or target.is_symlink():
                    raise CompositionError(f"application symlink collides with base: {source.name}")
                os.symlink(checked_link_target(source, target, root), target)
            else:
                raise CompositionError(f"application entry is not a regular file or directory: {source.name}")
    finally:
        destination.chmod(original_mode)


def extract_ext4(image, destination):
    regular(image, "ext4 input")
    destination.mkdir(mode=0o700)
    # The private path is deliberately allocated under /tmp with a fixed-safe
    # prefix: debugfs -R has its own command parser, not shell argument rules.
    if any(character.isspace() or character in '"\\' for character in str(destination)):
        raise CompositionError("private extraction path cannot be represented safely to debugfs")
    command = ["debugfs", "-R", f"rdump / {destination}", str(image)]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                check=False, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CompositionError(f"ext4 extraction could not complete: {error}") from error
    if result.returncode != 0:
        raise CompositionError("ext4 extraction failed")
    if not any(destination.iterdir()):
        raise CompositionError("ext4 extraction produced an empty tree")


def build_once(candidate, rootfs_name, pinned_mvmctl, workspace, reproducer):
    base_tree = workspace / "base"
    app_tree = workspace / "application"
    extract_ext4(candidate / "base" / rootfs_name, base_tree)
    extract_ext4(candidate / "layer" / "rootfs.ext4", app_tree)
    # Both mkfs outputs contain a filesystem-maintenance directory. It is not
    # application content and would otherwise collide with the base copy.
    lost_found = app_tree / "lost+found"
    if lost_found.exists():
        directory(lost_found, "application lost+found")
        if any(lost_found.iterdir()):
            raise CompositionError("application lost+found must be empty")
        lost_found.rmdir()
    merge_additive(app_tree, base_tree)
    output = workspace / "built"
    try:
        result = subprocess.run(
            [str(pinned_mvmctl), "image", "build-layer", "--source", str(base_tree),
             "--output", str(output)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=3600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CompositionError(f"composed rootfs builder could not complete: {error}") from error
    if result.returncode != 0:
        raise CompositionError(f"composed rootfs builder failed with exit status {result.returncode}")
    try:
        reproducer.verify_output(output)
    except reproducer.ReproductionError as error:
        raise CompositionError("composed rootfs asset report is invalid") from error
    return output


def compare_builds(first, second):
    reproducer = load_helper("reproduce-app-layer.py", "reproduce_app_layer_compare")
    if {entry.name for entry in first.iterdir()} != OUTPUTS or {entry.name for entry in second.iterdir()} != OUTPUTS:
        raise CompositionError("composed image output has missing or extra files")
    try:
        if reproducer.verify_output(first) != reproducer.verify_output(second):
            raise CompositionError("independent composed image builds differ")
    except reproducer.ReproductionError as error:
        raise CompositionError("independent composed image builds differ") from error
    if any(not reproducer.same_bytes(first / name, second / name) for name in OUTPUTS):
        raise CompositionError("independent composed image builds differ")


def compose(candidate, reference, mvmctl, mvmctl_sha256, output):
    candidate, mvmctl, output = map(Path, (candidate, mvmctl, output))
    base = load_helper("verify-base-set.py", "verify_base_set")
    reproducer = load_helper("reproduce-app-layer.py", "reproduce_app_layer")
    binder = load_helper("bind-image-candidate.py", "bind_image_candidate")
    parent = output.parent.resolve(strict=True)
    if output.name in ("", ".", "..") or output.exists() or output.is_symlink():
        raise CompositionError("output must name a new directory")
    with tempfile.TemporaryDirectory(prefix="mvm-pack-compose-", dir="/tmp") as private:
        private = Path(private)
        try:
            pinned = reproducer.pin_binary(mvmctl, mvmctl_sha256, private)
        except reproducer.ReproductionError as error:
            raise CompositionError("selected mvmctl cannot be pinned") from error
        snapshot = private / "candidate"
        snapshot_candidate(candidate, snapshot, binder)
        pack_source = staged_pack_source(snapshot, reference, private, binder)
        report, rootfs_name = check_candidate(
            snapshot, pack_source, pinned, mvmctl_sha256, base, reproducer
        )
        first = private / "first"
        second = private / "second"
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        first_output = build_once(snapshot, rootfs_name, pinned, first, reproducer)
        second_output = build_once(snapshot, rootfs_name, pinned, second, reproducer)
        compare_builds(first_output, second_output)
        with tempfile.TemporaryDirectory(prefix=".mvm-composed-", dir=parent) as staging:
            staged = Path(staging) / "unsigned-composed-image"
            staged.mkdir(mode=0o700)
            for name in sorted(OUTPUTS):
                shutil.copyfile(first_output / name, staged / name)
            try:
                records = reproducer.verify_output(staged)
            except reproducer.ReproductionError as error:
                raise CompositionError("copied composed assets differ from their report") from error
            composition = {
                "schema_version": 1,
                "kind": "unsigned-composed-image",
                "base_set": report["base_set"],
                "candidate_sha256": reproducer.digest_file(snapshot / "candidate.json")[0],
                "application_layer_sha256": report["application_layer"]["rootfs.ext4"]["sha256"],
                "verifier_sha256": mvmctl_sha256,
                "assets": {
                    name: {"sha256": digest, "size": size}
                    for name, (digest, size) in sorted(records.items())
                },
            }
            (staged / "composition.json").write_text(
                json.dumps(composition, sort_keys=True, separators=(",", ":")) + "\n"
            )
            reproducer.publish_noclobber(staged, parent / output.name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--mvmctl", required=True, type=Path)
    parser.add_argument("--mvmctl-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        compose(args.candidate, args.reference, args.mvmctl, args.mvmctl_sha256, args.output)
    except (OSError, ValueError, CompositionError) as error:
        parser.exit(1, f"compose-pack-image: {error}\n")
    except SystemExit as error:
        parser.exit(1, f"compose-pack-image: verification failed: {error}\n")


if __name__ == "__main__":
    main()
