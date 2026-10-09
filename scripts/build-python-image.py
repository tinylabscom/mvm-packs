#!/usr/bin/env python3
"""Build a reproduced unsigned runtime/python image inside the project builder VM.

This command does not sign, attest, upload, or publish a pack. Its output is
only input evidence for the main publisher workflow identity.
"""

import argparse
import importlib.util
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCE = ROOT / "pack-sources/runtime/python/pack.toml"
PIN = re.compile(r"[0-9a-f]{64}\n?\Z")


class BuildError(Exception):
    """The unsigned image could not be produced or verified completely."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise BuildError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = helper("stage-python-closure.py", "stage_python_closure_builder")
reproducer = helper("reproduce-app-layer.py", "reproduce_app_layer_builder")
binder = helper("bind-image-candidate.py", "bind_image_candidate_builder")
composer = helper("compose-pack-image.py", "compose_pack_image_builder")
base = helper("verify-base-set.py", "verify_base_set_builder")
catalog = helper("build-packs.py", "build_packs_builder")
signer = helper("sign-composed-image.py", "sign_composed_image_builder")


def read_pin(path):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BuildError("no-follow client pin reading is unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BuildError("client digest pin must be a regular file")
        with os.fdopen(descriptor, "r", encoding="ascii", closefd=False) as handle:
            value = handle.read(67)
    finally:
        os.close(descriptor)
    if not PIN.fullmatch(value):
        raise BuildError("client digest pin must be one lowercase SHA-256")
    return value.strip()


def preflight(pack_source, binary, pin_file, manifest, bundle, artifacts, output):
    if sys.platform != "linux":
        raise BuildError("Python image builds must run inside the Linux builder VM")
    pack_source, binary, pin_file, manifest, bundle, artifacts, output = map(
        Path, (pack_source, binary, pin_file, manifest, bundle, artifacts, output)
    )
    if (pack_source.resolve(strict=True) != PYTHON_SOURCE.resolve(strict=True)
            or not stat.S_ISREG(pack_source.lstat().st_mode)):
        raise BuildError("pack source must be the checked-in runtime/python intent")
    if output.name in ("", ".", "..") or output.exists() or output.is_symlink():
        raise BuildError("output must name a new directory")
    parent = output.parent.resolve(strict=True)
    if (not stat.S_ISDIR(output.parent.lstat().st_mode)
            or parent == ROOT or ROOT in parent.parents):
        raise BuildError("output must be a real directory outside the repository")
    image = base.source_image(pack_source)
    metadata = catalog.parse_pack_toml(pack_source)
    if metadata["image_build"] is None or image["platform"] != "linux/x86_64":
        raise BuildError("runtime/python image intent must target linux/x86_64")
    digest = read_pin(pin_file)
    expected, _ = base.expected_artifacts(image["platform"])
    base.check_inputs(binary, digest, manifest, bundle, artifacts, expected)
    if not binary.lstat().st_mode & 0o111 or reproducer.digest_file(binary)[0] != digest:
        raise BuildError("client digest or executable mode differs from the verified release")
    return f"runtime/python@{metadata['version']}", digest, parent / output.name


def build(pack_source, binary, pin_file, manifest, bundle, artifacts, output):
    pack_source, binary, manifest, bundle, artifacts = map(
        Path, (pack_source, binary, manifest, bundle, artifacts)
    )
    try:
        reference, digest, destination = preflight(
            pack_source, binary, pin_file, manifest, bundle, artifacts, output
        )
        with tempfile.TemporaryDirectory(prefix="mvm-python-image-", dir="/tmp") as private:
            private = Path(private)
            tree = private / "python-tree"
            stage.build_and_stage(tree)
            layer = private / "layer"
            reproducer.reproduce(tree, binary, digest, layer)
            candidate = private / "candidate"
            binder.bind(pack_source, binary, digest, manifest, bundle, artifacts, layer, candidate)
            composition = private / "composition"
            composer.compose(candidate, reference, binary, digest, composition)
            with tempfile.TemporaryDirectory(
                prefix=".mvm-python-export-", dir=destination.parent
            ) as staging:
                staged = Path(staging) / "unsigned-python-image"
                staged.mkdir(mode=0o700)
                binder.copy_regular(candidate / "candidate.json", staged / "candidate.json")
                binder.copy_exact(
                    composition, staged / "composition",
                    signer.INPUT_ASSETS | {"composition.json"}, "composed image",
                )
                signer.validate_snapshot(
                    staged / "composition", staged / "candidate.json",
                    reference, reproducer,
                )
                reproducer.publish_noclobber(staged, destination)
    except (OSError, UnicodeError, ValueError, SystemExit,
            stage.StageError, reproducer.ReproductionError,
            binder.CandidateError, composer.CompositionError,
            signer.SigningError) as error:
        raise BuildError(str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvmctl", required=True, type=Path)
    parser.add_argument("--mvmctl-sha256-file", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        build(args.pack_source, args.mvmctl, args.mvmctl_sha256_file,
              args.manifest, args.bundle, args.artifacts, args.output)
    except BuildError as error:
        parser.exit(1, f"build-python-image: {error}\n")


if __name__ == "__main__":
    main()
