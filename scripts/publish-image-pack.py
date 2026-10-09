#!/usr/bin/env python3
"""Sign a registry pack only after its published image release is reverified."""

import argparse
import importlib.util
import os
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


def copy_payload(source, destination):
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise PublishError("pack payload must be a directory, not a link")
    before = set()
    for entry in source.rglob("*"):
        relative = entry.relative_to(source)
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise PublishError(f"pack payload symlink is not allowed: {relative}")
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise PublishError(f"pack payload special file is not allowed: {relative}")
        before.add(relative)
        if stat.S_ISDIR(mode):
            (destination / relative).mkdir(parents=True, exist_ok=True)
        else:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                binder.copy_regular(entry, target)
            except (OSError, binder.CandidateError) as error:
                raise PublishError(f"pack payload changed while copying: {relative}") from error
    if before != {entry.relative_to(source) for entry in source.rglob("*")}:
        raise PublishError("pack payload file set changed while copying")


def publish(source, evidence, images_lock, environment, client):
    source, evidence, images_lock = map(Path, (source, evidence, images_lock))
    namespace, name = source.parent.name, source.name
    if not builder.COORD.fullmatch(namespace) or not builder.COORD.fullmatch(name):
        raise PublishError("pack namespace or name is invalid")
    try:
        metadata = builder.parse_pack_toml(source / "pack.toml")
    except SystemExit as error:
        raise PublishError("pack source metadata is invalid") from error
    if metadata["image_build"] is None or metadata["image"] is not None:
        raise PublishError("pack source must declare only measured image build intent")
    reference = f"{namespace}/{name}@{metadata['version']}"
    output = builder.PACKS / namespace / name / metadata["version"]
    if output.exists() or output.is_symlink():
        raise PublishError("immutable pack version already exists")
    payload = source / "pack"
    if not payload.is_dir() or payload.is_symlink():
        raise PublishError("pack source has no regular payload directory")
    try:
        signer.check_identity(environment)
    except signer.SigningError as error:
        raise PublishError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="mvm-pack-registry-", dir="/tmp") as temporary:
        private = Path(temporary)
        staged_release = private / "release"
        try:
            stager.stage(evidence, reference, source / "pack.toml", images_lock,
                         staged_release)
            descriptor = stager.read_json(staged_release / "image-descriptor.json")
            uploader.verify_published(staged_release, descriptor, reference,
                                      environment, client)
        except (stager.StageError, uploader.UploadError) as error:
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
    args = parser.parse_args(argv)
    try:
        client = uploader.GithubReleaseClient(os.environ.get("GITHUB_TOKEN"))
        output = publish(args.pack_source, args.evidence, args.mvm_images_lock,
                         os.environ, client)
        print(f"published verified registry pack {output.relative_to(builder.PACKS)}")
    except (OSError, ValueError, PublishError, uploader.UploadError) as error:
        parser.exit(1, f"publish-image-pack: {error}\n")


if __name__ == "__main__":
    main()
