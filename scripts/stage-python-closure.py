#!/usr/bin/env python3
"""Build pinned CPython inside the builder VM and stage its full guest closure."""

import argparse
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


IMAGE_FLAKE = Path(__file__).resolve().parents[1] / "pack-sources/runtime/python/image"
STORE_ROOT = Path("/nix/store")
STORE_NAME = re.compile(r"[0-9a-z]{32}-[A-Za-z0-9+._-]+\Z")


class StageError(Exception):
    """The pinned interpreter closure cannot be staged safely."""


def reproducer_helper():
    script = Path(__file__).with_name("reproduce-app-layer.py")
    spec = importlib.util.spec_from_file_location("reproduce_for_python_stage", script)
    if spec is None or spec.loader is None:
        raise StageError("atomic output publication helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def store_member(path, store_root):
    path = Path(path)
    if path.parent != store_root or not STORE_NAME.fullmatch(path.name):
        raise StageError("Nix closure contains a non-directory or out-of-store member")
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise StageError("Nix closure member is unavailable") from error
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise StageError("Nix closure contains a special or linked store member")
    return path


def stage_closure(python_out, requisites, output, store_root=STORE_ROOT):
    store_root, output = Path(store_root), Path(output)
    python_out = store_member(python_out, store_root)
    if not stat.S_ISDIR(python_out.lstat().st_mode):
        raise StageError("Python output is not a store directory")
    paths = [store_member(path, store_root) for path in requisites]
    if len(paths) != len(set(paths)) or python_out not in paths:
        raise StageError("Nix closure is duplicate or omits the Python output")
    executable = python_out / "bin/python3"
    if (not executable.is_file() or not os.access(executable, os.X_OK)
            or store_root.resolve(strict=True) not in executable.resolve(strict=True).parents):
        raise StageError("Python executable is missing or not executable")
    if output.name in ("", ".", "..") or output.exists() or output.is_symlink():
        raise StageError("output already exists or has no name")
    parent = output.parent.resolve(strict=True)
    if parent == store_root or store_root in parent.parents:
        raise StageError("output cannot be placed in the Nix store")
    with tempfile.TemporaryDirectory(prefix=".mvm-python-stage-", dir=parent) as temporary:
        tree = Path(temporary) / "root"
        destination = tree / "nix/store"
        destination.mkdir(parents=True)
        for path in sorted(paths):
            if stat.S_ISDIR(path.lstat().st_mode):
                shutil.copytree(path, destination / path.name, symlinks=True)
            else:
                shutil.copy2(path, destination / path.name, follow_symlinks=False)
        (tree / "bin").mkdir()
        (tree / "bin/python3").symlink_to(f"/nix/store/{python_out.name}/bin/python3")
        reproducer = reproducer_helper()
        try:
            reproducer.publish_noclobber(tree, parent / output.name)
        except (OSError, reproducer.ReproductionError) as error:
            raise StageError("staged Python tree could not be published without replacement") from error


def run_nix(arguments):
    try:
        with tempfile.TemporaryDirectory(prefix="mvm-python-nix-cache-", dir="/tmp") as cache:
            environment = os.environ.copy()
            environment["XDG_CACHE_HOME"] = cache
            result = subprocess.run(arguments, capture_output=True, text=True,
                                    check=False, timeout=3600, env=environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise StageError("pinned Nix command could not complete") from error
    if result.returncode != 0:
        raise StageError(f"pinned Nix command failed with exit status {result.returncode}")
    return [line for line in result.stdout.splitlines() if line]


def build_and_stage(output):
    if not sys.platform.startswith("linux"):
        raise StageError("CPython must be built inside the Linux builder VM")
    if not IMAGE_FLAKE.joinpath("flake.nix").is_file() or not IMAGE_FLAKE.joinpath("flake.lock").is_file():
        raise StageError("pinned Python flake and lock are required")
    built = run_nix([
        "nix", "--extra-experimental-features", "nix-command flakes", "build",
        "--no-link", "--print-out-paths", "--no-update-lock-file",
        f"path:{IMAGE_FLAKE}#default",
    ])
    if len(built) != 1:
        raise StageError("pinned Python build produced no unique store output")
    closure = run_nix(["nix-store", "--query", "--requisites", built[0]])
    stage_closure(built[0], closure, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new staged guest tree")
    args = parser.parse_args(argv)
    try:
        build_and_stage(args.output)
    except (OSError, StageError) as error:
        parser.exit(1, f"stage-python-closure: {error}\n")


if __name__ == "__main__":
    main()
