#!/usr/bin/env python3
"""Bind verified base inputs and a reproduced layer into an unsigned candidate."""

import argparse
import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path


def load_helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise CandidateError(f"{filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CandidateError(Exception):
    """The candidate cannot be safely bound."""


def directory(path, label):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise CandidateError(f"{label} must be a directory, not a link")


def copy_regular(source, target):
    """Copy an exact leaf through a no-follow descriptor into private storage."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise CandidateError("no-follow file copying is unavailable")
    descriptor = os.open(source, os.O_RDONLY | nofollow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CandidateError(f"input is not a regular file: {source}")
        target_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as input_file, \
                    os.fdopen(target_descriptor, "wb", closefd=False) as output_file:
                for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                    output_file.write(chunk)
        finally:
            os.close(target_descriptor)
    finally:
        os.close(descriptor)


def copy_exact(source, target, names, label):
    directory(source, label)
    if {entry.name for entry in source.iterdir()} != set(names):
        raise CandidateError(f"{label} has missing or extra files")
    target.mkdir(mode=0o700)
    for name in sorted(names):
        copy_regular(source / name, target / name)


def file_record(path, reproducer):
    digest, size = reproducer.digest_file(path)
    if size <= 0:
        raise CandidateError(f"empty candidate input: {path.name}")
    return {"sha256": digest, "size": size}


def bind(pack_source, mvmctl, mvmctl_sha256, manifest, bundle, artifacts, layer, output):
    base = load_helper("verify-base-set.py", "verify_base_set")
    reproducer = load_helper("reproduce-app-layer.py", "reproduce_app_layer")
    pack_source, mvmctl, manifest, bundle, artifacts, layer, output = map(
        Path, (pack_source, mvmctl, manifest, bundle, artifacts, layer, output)
    )
    if pack_source.name != "pack.toml":
        raise CandidateError("pack source must be named pack.toml")
    image = base.source_image(pack_source)
    expected, _ = base.expected_artifacts(image["platform"])
    base.check_inputs(mvmctl, mvmctl_sha256, manifest, bundle, artifacts, expected)
    directory(layer, "application layer")
    parent = output.parent.resolve(strict=True)
    if output.name in ("", ".", "..") or output.exists() or output.is_symlink():
        raise CandidateError("output must name a new directory")
    output = parent / output.name
    for input_path in (pack_source, mvmctl, manifest, bundle, artifacts, layer):
        resolved = input_path.resolve(strict=True)
        if resolved == parent or resolved in parent.parents:
            raise CandidateError("output must be outside all candidate inputs")

    with tempfile.TemporaryDirectory(prefix=".mvm-candidate-", dir=parent) as temporary:
        private = Path(temporary)
        staged_source = private / "pack-sources" / pack_source.parent.parent.name / pack_source.parent.name
        staged_source.mkdir(parents=True, mode=0o700)
        copy_regular(pack_source, staged_source / "pack.toml")
        staged_manifest = private / "image-set.json"
        staged_bundle = private / "image-set.json.bundle"
        copy_regular(manifest, staged_manifest)
        copy_regular(bundle, staged_bundle)
        staged_base = private / "base"
        copy_exact(artifacts, staged_base, expected, "base artifact directory")
        staged_layer = private / "layer"
        copy_exact(layer, staged_layer, reproducer.OUTPUTS, "application layer")
        try:
            pinned = reproducer.pin_binary(mvmctl, mvmctl_sha256, private)
        except reproducer.ReproductionError as error:
            raise CandidateError(str(error)) from error
        base.verify_base_set(
            staged_source / "pack.toml", pinned, mvmctl_sha256,
            staged_manifest, staged_bundle, staged_base,
        )
        try:
            layer_records = reproducer.verify_output(staged_layer)
        except reproducer.ReproductionError as error:
            raise CandidateError(str(error)) from error
        image = base.source_image(staged_source / "pack.toml")
        descriptor = {
            "schema_version": 1,
            "kind": "unsigned-image-candidate",
            "platform": image["platform"],
            "pack_source": file_record(staged_source / "pack.toml", reproducer),
            "base_set": image["base_set"],
            "signed_root_manifest": file_record(staged_manifest, reproducer),
            "signed_root_bundle": file_record(staged_bundle, reproducer),
            "verifier_sha256": mvmctl_sha256,
            "verification_scope": "selected-base-artifacts-only",
            "base_artifacts": {
                name: file_record(staged_base / name, reproducer) for name in sorted(expected)
            },
            "application_layer": {
                name: {"sha256": digest, "size": size}
                for name, (digest, size) in sorted(layer_records.items())
            },
        }
        candidate = private / "candidate"
        candidate.mkdir(mode=0o700)
        (candidate / "candidate.json").write_text(
            json.dumps(descriptor, sort_keys=True, separators=(",", ":")) + "\n"
        )
        (staged_source / "pack.toml").rename(candidate / "pack.toml")
        staged_manifest.rename(candidate / "image-set.json")
        staged_bundle.rename(candidate / "image-set.json.bundle")
        staged_base.rename(candidate / "base")
        staged_layer.rename(candidate / "layer")
        try:
            reproducer.publish_noclobber(candidate, output)
        except reproducer.ReproductionError as error:
            raise CandidateError(str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvmctl", required=True, type=Path)
    parser.add_argument("--mvmctl-sha256", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--layer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        bind(args.pack_source, args.mvmctl, args.mvmctl_sha256, args.manifest,
             args.bundle, args.artifacts, args.layer, args.output)
    except (OSError, ValueError, CandidateError) as error:
        parser.exit(1, f"bind-image-candidate: {error}\n")
    except SystemExit as error:
        parser.exit(1, f"bind-image-candidate: base verification failed: {error}\n")

if __name__ == "__main__":
    main()
