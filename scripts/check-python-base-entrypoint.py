#!/usr/bin/env python3
"""Bind a Python pack sidecar's boot argv to the selected signed base rootfs."""

import argparse
import hashlib
import importlib.util
import json
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import NamedTuple


class EntrypointError(Exception):
    """The sidecar does not describe the pinned base entrypoint."""


class BaseEntrypointPin(NamedTuple):
    base_set: dict[str, str]
    rootfs_sha256: str
    marker_sha256: str
    argv: tuple[str, ...]


PIN = BaseEntrypointPin(
    base_set={
        "repository": "tinylabscom/mvm-images",
        "release_tag": "image-set/v0.2.4",
        "manifest_sha256": "5033520a59514f5d206d76d13db8c9b7e5841f068c83dd8585ef141879a1bb24",
    },
    rootfs_sha256="b1864b5c90ca32d6f1c3f3f609acdc88fd39fccd379c4a0acbe0537f3127c08c",
    marker_sha256="81b28e07161ac65d7523f2e8a027310cc9d11cd480a0e618633c576554a79d44",
    argv=("/bin/sleep", "infinity"),
)


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise EntrypointError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(rootfs, pack_source, sidecar, pin=PIN):
    rootfs, pack_source, sidecar = map(Path, (rootfs, pack_source, sidecar))
    if rootfs.name != "default-microvm-rootfs-x86_64.ext4" or not stat.S_ISREG(
        rootfs.lstat().st_mode
    ):
        raise EntrypointError("selected base must be a regular rootfs asset")
    binder = helper("bind-image-candidate.py", "bind_image_entrypoint_check")
    reproducer = helper("reproduce-app-layer.py", "reproduce_entrypoint_check")
    with tempfile.TemporaryDirectory(prefix="mvm-python-entrypoint-", dir="/tmp") as temporary:
        private = Path(temporary)
        try:
            binder.copy_regular(rootfs, private / rootfs.name)
            binder.copy_regular(pack_source, private / "pack.toml")
            binder.copy_regular(sidecar, private / "mvm-meta.json")
        except (OSError, binder.CandidateError) as error:
            raise EntrypointError("base, source, or sidecar must be a regular input") from error
        digest, size = reproducer.digest_file(private / rootfs.name)
        if size == 0 or digest != pin.rootfs_sha256:
            raise EntrypointError("selected base rootfs digest differs from the pinned release")
        try:
            source = tomllib.loads((private / "pack.toml").read_text(encoding="utf-8"))
            metadata = json.loads(
                (private / "mvm-meta.json").read_bytes(),
                object_pairs_hook=reproducer.unique_object,
            )
        except (UnicodeError, ValueError, tomllib.TOMLDecodeError,
                reproducer.ReproductionError) as error:
            raise EntrypointError("pack source or sidecar is invalid") from error
        intent = source.get("image_build") if isinstance(source, dict) else None
        if (not isinstance(intent, dict)
                or intent.get("platform") != "linux/x86_64"
                or intent.get("base_set") != pin.base_set):
            raise EntrypointError("pack source base set differs from the inspected rootfs pin")
        if not isinstance(metadata, dict) or metadata.get("entrypointArgv") != list(pin.argv):
            raise EntrypointError("sidecar entrypoint argv differs from the pinned base")
        try:
            result = subprocess.run(
                ["debugfs", "-R", "cat /etc/mvm/entrypoint", str(private / rootfs.name)],
                capture_output=True, check=False, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EntrypointError("base entrypoint could not be inspected") from error
        if (result.returncode != 0 or not result.stdout
                or len(result.stdout) > 8192
                or hashlib.sha256(result.stdout).hexdigest() != pin.marker_sha256):
            raise EntrypointError("base entrypoint bytes differ from the pinned release")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvm-meta", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        verify(args.rootfs, args.pack_source, args.mvm_meta)
    except (OSError, EntrypointError) as error:
        parser.exit(1, f"check-python-base-entrypoint: {error}\n")


if __name__ == "__main__":
    main()
