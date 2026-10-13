#!/usr/bin/env python3
"""Prepare unsigned private candidates; publish only after public release verification."""

import argparse
import importlib.util
import os
import secrets
import shutil
import stat
import tempfile
from pathlib import Path


class PublishError(Exception):
    """The signed image is not eligible for registry publication."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise PublishError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = helper("build-packs.py", "build_packs_image_publish")
stager = helper("stage-image-release.py", "stage_image_registry_publish")
uploader = helper("upload-image-release.py", "upload_image_registry_publish")
signer = helper("sign-composed-image.py", "sign_image_registry_publish")
binder = helper("bind-image-candidate.py", "bind_image_registry_publish")
reproducer = helper("reproduce-app-layer.py", "reproduce_image_registry_publish")

# Explicit preparation storage limits, not changes to image trust semantics.
MAX_PAYLOAD_FILES = 4096
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = stager.MAX_METADATA_BYTES


def read_snapshot_json(path):
    """Parse metadata only after a bounded regular-file snapshot."""
    with tempfile.TemporaryDirectory(prefix="mvm-pack-json-", dir="/tmp") as temporary:
        copied = Path(temporary) / path.name
        try:
            binder.copy_regular(path, copied, max_bytes=MAX_METADATA_BYTES)
        except (OSError, binder.CandidateError) as error:
            raise PublishError("metadata snapshot refused linked, special or oversized input") from error
        return stager.read_json(copied)


def copy_payload(source, destination):
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise PublishError("pack payload must be a directory, not a link")
    before = set()
    copied_bytes = 0
    for entry in source.rglob("*"):
        relative = entry.relative_to(source)
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise PublishError(f"pack payload symlink is not allowed: {relative}")
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise PublishError(f"pack payload special file is not allowed: {relative}")
        before.add(relative)
        if len(before) > MAX_PAYLOAD_FILES:
            raise PublishError("pack payload exceeds entry bound")
        if stat.S_ISDIR(mode):
            (destination / relative).mkdir(parents=True, exist_ok=True)
        else:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                binder.copy_regular(entry, target,
                                    max_bytes=MAX_PAYLOAD_BYTES - copied_bytes)
                copied_bytes += target.stat().st_size
            except (OSError, binder.CandidateError) as error:
                raise PublishError(f"pack payload changed while copying: {relative}") from error
    if before != {entry.relative_to(source) for entry in source.rglob("*")}:
        raise PublishError("pack payload file set changed while copying")


def prepare(source, evidence, images_lock, private, *, local_transport=False):
    """Verify evidence and render the same unsigned bytes used by publication."""
    source, evidence, images_lock = map(Path, (source, evidence, images_lock))
    namespace, name = source.parent.name, source.name
    if not builder.COORD.fullmatch(namespace) or not builder.COORD.fullmatch(name):
        raise PublishError("pack namespace or name is invalid")
    snapshot_source = private / "pack-sources" / namespace / name / "pack.toml"
    snapshot_source.parent.mkdir(parents=True, mode=0o700)
    try:
        binder.copy_regular(source / "pack.toml", snapshot_source,
                            max_bytes=MAX_METADATA_BYTES)
    except (OSError, binder.CandidateError) as error:
        raise PublishError("pack source metadata snapshot failed") from error
    try:
        metadata = builder.parse_pack_toml(snapshot_source)
    except SystemExit as error:
        raise PublishError("pack source metadata is invalid") from error
    if metadata["image_build"] is None or metadata["image"] is not None:
        raise PublishError("pack source must declare only measured image build intent")
    reference = f"{namespace}/{name}@{metadata['version']}"
    payload = source / "pack"
    if not payload.is_dir() or payload.is_symlink():
        raise PublishError("pack source has no regular payload directory")
    staged_release = private / "release"
    try:
        stager.stage(evidence, reference, snapshot_source, images_lock,
                     staged_release)
        descriptor = read_snapshot_json(staged_release / "image-descriptor.json")
    except stager.StageError as error:
        raise PublishError(str(error)) from error
    registry = private / "registry"
    registry_payload = registry / "files" / "pack"
    registry_payload.mkdir(parents=True)
    copy_payload(payload, registry_payload)
    try:
        manifest, _ = builder.manifest_bytes(reference, metadata["description"],
                                             registry_payload, descriptor)
    except SystemExit as error:
        raise PublishError("measured descriptor or signed payload is invalid") from error
    (registry / "manifest.json").write_bytes(manifest)
    if local_transport:
        for asset in descriptor["assets"].values():
            target = registry / "files" / asset["name"]
            if target.exists() or target.is_symlink():
                raise PublishError("image asset collides with registry payload")
            try:
                binder.copy_regular(staged_release / asset["name"], target,
                                    max_bytes=asset["size"])
            except (OSError, binder.CandidateError) as error:
                raise PublishError("verified image asset transport copy failed") from error
            if stager.record(target) != {"sha256": asset["sha256"], "size": asset["size"]}:
                raise PublishError("verified image asset changed during transport copy")
    snapshot_source.unlink()
    snapshot_source.parent.rmdir()
    snapshot_source.parent.parent.rmdir()
    (private / "pack-sources").rmdir()
    return reference, descriptor


def prepare_private(source, evidence, images_lock, output):
    """Write an unsigned candidate inside this checkout, without signing or upload."""
    output = Path(os.path.abspath(output))
    workspace = Path(__file__).resolve().parents[1]
    if not output.is_relative_to(workspace) or output == workspace:
        raise PublishError("private candidate output must be inside the workspace")
    parent_fd = open_output_parent(output.parent, workspace)
    try:
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PublishError("private candidate output must be a new directory")
        with tempfile.TemporaryDirectory(prefix="mvm-private-registry-", dir="/tmp") as temporary:
            private = Path(temporary) / "candidate"
            private.mkdir(mode=0o700)
            prepare(source, evidence, images_lock, private, local_transport=True)
            # Detect an ancestor replacement before any output staging writes.
            check_fd = open_output_parent(output.parent, workspace, create=False)
            try:
                if (os.fstat(check_fd).st_dev, os.fstat(check_fd).st_ino) != (
                        os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino):
                    raise PublishError("private output parent changed during preparation")
            finally:
                os.close(check_fd)
            publish_prepared(private, output.name, parent_fd)
    finally:
        os.close(parent_fd)
    return output


def directory_flags():
    flags = getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if (not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0)
            or os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or not shutil.rmtree.avoids_symlink_attacks):
        raise PublishError("safe fd-relative output publication is unavailable")
    return os.O_RDONLY | flags


def open_output_parent(parent, workspace, *, create=True):
    """Capture a directory through no-follow ancestors; create only inside workspace."""
    flags = directory_flags()
    descriptor = os.open(parent.anchor, flags)
    walked = Path(parent.anchor)
    try:
        for component in parent.parts[1:]:
            walked /= component
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create or not walked.is_relative_to(workspace):
                    raise
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise PublishError("private output ancestor is missing, linked or changed") from error


def publish_prepared(private, output_name, parent_fd):
    """Stage via the existing regular copier and rename through held directory fds."""
    flags = directory_flags()
    staging_name = ".mvm-private-registry-" + secrets.token_hex(16)
    os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
    staging_fd = os.open(staging_name, flags, dir_fd=parent_fd)
    published = False

    def stage_directory(source, destination_fd, depth=0):
        if depth > 64:
            raise PublishError("prepared output exceeds depth bound")
        for entry in source.iterdir():
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                os.mkdir(entry.name, mode=0o700, dir_fd=destination_fd)
                child = os.open(entry.name, flags, dir_fd=destination_fd)
                try:
                    stage_directory(entry, child, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                binder.copy_regular(entry, entry.name, max_bytes=info.st_size,
                                    target_dir_fd=destination_fd)
            else:
                raise PublishError("prepared output has a linked or special file")

    try:
        stage_directory(private, staging_fd)
        reproducer.publish_noclobber(
            staging_name, output_name, source_dir_fd=parent_fd, destination_dir_fd=parent_fd)
        published = True
    except (OSError, binder.CandidateError, reproducer.ReproductionError) as error:
        raise PublishError("private candidate could not be written") from error
    finally:
        os.close(staging_fd)
        if not published:
            shutil.rmtree(staging_name, dir_fd=parent_fd)


def candidate_inventory(candidate):
    """Bound traversal and retain identities for a final no-mutation check."""
    inventory = {}
    pending = [(candidate, 0)]
    while pending:
        directory, depth = pending.pop()
        if depth > 64:
            raise PublishError("candidate inventory exceeds depth bound")
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise PublishError("candidate comparison requires regular directories")
        relative = directory.relative_to(candidate)
        inventory[relative] = (info.st_dev, info.st_ino, info.st_mode,
                               info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(inventory) + len(pending) >= MAX_PAYLOAD_FILES + 64:
                    raise PublishError("candidate inventory exceeds entry bound")
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    inventory[path.relative_to(candidate)] = (
                        info.st_dev, info.st_ino, info.st_mode, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
                else:
                    raise PublishError("candidate comparison refused linked or special input")
    return inventory


def compare_candidate(private, candidate):
    """Fail closed on regeneration drift; never accept candidate manifest input."""
    candidate = Path(candidate)
    before = candidate_inventory(candidate)
    if {path.parts[0] for path in before if path.parts} != {"registry", "release"}:
        raise PublishError("candidate inventory changed; re-observation required")
    descriptor = read_snapshot_json(private / "release" / "image-descriptor.json")
    transport_files = {
        Path("files") / asset["name"]: private / "release" / asset["name"]
        for asset in descriptor["assets"].values()
    }
    for name in ("registry", "release"):
        actual, expected = private / name, candidate / name
        actual_files = {p.relative_to(actual) for p in actual.rglob("*") if p.is_file()}
        expected_files = {Path(*path.parts[1:]) for path, identity in before.items()
                          if path.parts and path.parts[0] == name
                          and stat.S_ISREG(identity[2])}
        # A protected publisher may have supplied the manifest bundle after
        # preparation. Its identity is verified elsewhere, never by this comparison.
        if name == "registry":
            expected_files.discard(Path("manifest.sigstore.json"))
        comparison_files = dict.fromkeys(actual_files)
        if name == "registry":
            if actual_files.intersection(transport_files):
                raise PublishError("image asset collides with regenerated registry payload")
            comparison_files.update(transport_files)
        if set(comparison_files) != expected_files:
            raise PublishError("candidate inventory changed; re-observation required")
        records = {relative: stager.record(source or actual / relative)
                   for relative, source in comparison_files.items()}
        # Aggregate storage is bounded by the regenerated trusted inventory,
        # not a second limit that charges image bytes to the source payload.
        budget = sum(record["size"] for record in records.values())
        observed = sum(before[Path(name) / relative][3] for relative in expected_files)
        if name == "registry" and Path(name) / "manifest.sigstore.json" in before:
            budget += MAX_METADATA_BYTES
            observed += before[Path(name) / "manifest.sigstore.json"][3]
        if observed > budget:
            raise PublishError(
                "candidate bytes changed; aggregate snapshot bound exceeded; re-observation required")
        with tempfile.TemporaryDirectory(prefix="mvm-pack-compare-", dir="/tmp") as temporary:
            snapshot = Path(temporary) / "file"
            for relative, record in records.items():
                identity = before[Path(name) / relative]
                if identity[3] != record["size"]:
                    raise PublishError("candidate bytes changed; re-observation required")
                try:
                    binder.copy_regular(expected / relative, snapshot,
                                        max_bytes=record["size"])
                except (OSError, binder.CandidateError) as error:
                    raise PublishError("candidate snapshot refused changed or special input") from error
                if stager.record(snapshot) != record:
                    raise PublishError("candidate bytes changed; re-observation required")
                snapshot.unlink()
            if name == "registry" and Path(name) / "manifest.sigstore.json" in before:
                try:
                    binder.copy_regular(expected / "manifest.sigstore.json", snapshot,
                                        max_bytes=MAX_METADATA_BYTES)
                except (OSError, binder.CandidateError) as error:
                    raise PublishError("candidate bundle snapshot refused input") from error
    if candidate_inventory(candidate) != before:
        raise PublishError("candidate inventory changed during comparison; re-observation required")


def publish(source, evidence, images_lock, environment, client, candidate=None):
    source = Path(source)
    try:
        signer.check_identity(environment)
    except signer.SigningError as error:
        raise PublishError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="mvm-pack-registry-", dir="/tmp") as temporary:
        private = Path(temporary)
        reference, descriptor = prepare(source, evidence, images_lock, private)
        output = builder.PACKS / source.parent.name / source.name / reference.partition("@")[2]
        if output.exists() or output.is_symlink():
            raise PublishError("immutable pack version already exists")
        staged_release = private / "release"
        try:
            uploader.verify_published(staged_release, descriptor, reference,
                                      environment, client)
        except uploader.UploadError as error:
            raise PublishError(str(error)) from error
        registry = private / "registry"
        if candidate is not None:
            compare_candidate(private, candidate)
        try:
            signer.sign_and_verify(registry / "manifest.json",
                                   registry / "manifest.sigstore.json")
        except signer.SigningError as error:
            raise PublishError(str(error)) from error
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            reproducer.publish_noclobber(registry, output)
        except (OSError, reproducer.ReproductionError) as error:
            raise PublishError("immutable registry version could not be published") from error
    builder.rebuild_index()
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--mvm-images-lock", required=True, type=Path)
    parser.add_argument("--private-output", type=Path,
                        help="prepare an unsigned candidate inside the workspace; do not publish")
    parser.add_argument("--compare-candidate", type=Path,
                        help="require regenerated bytes to match an observed private candidate")
    args = parser.parse_args(argv)
    try:
        if args.private_output is not None:
            if args.compare_candidate is not None:
                raise PublishError("private preparation cannot compare a publication candidate")
            output = prepare_private(args.pack_source, args.evidence,
                                     args.mvm_images_lock, args.private_output)
            print(f"prepared unsigned private candidate {output}")
            return
        client = uploader.GithubReleaseClient(os.environ.get("GITHUB_TOKEN"))
        output = publish(args.pack_source, args.evidence, args.mvm_images_lock,
                         os.environ, client, args.compare_candidate)
        print(f"published verified registry pack {output.relative_to(builder.PACKS)}")
    except (OSError, ValueError, PublishError, uploader.UploadError) as error:
        parser.exit(1, f"publish-image-pack: {error}\n")


if __name__ == "__main__":
    main()
