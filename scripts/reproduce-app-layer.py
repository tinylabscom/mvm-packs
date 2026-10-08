#!/usr/bin/env python3
"""Rebuild an unsigned application layer twice and publish only identical bytes."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ASSETS = ("rootfs.ext4", "rootfs.verity", "rootfs.roothash")
OUTPUTS = frozenset((*ASSETS, "asset-report.json"))
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ReproductionError(Exception):
    """A candidate layer cannot be accepted for publication."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReproductionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def digest_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ReproductionError(f"not a regular file: {path}")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def pin_binary(binary, expected, private_directory):
    """Copy the selected executable from one no-follow descriptor into private storage."""
    if not HEX64.fullmatch(expected):
        raise ReproductionError("mvmctl SHA-256 must be 64 lowercase hexadecimal characters")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ReproductionError("no-follow executable pinning is unavailable")
    source_descriptor = os.open(binary, os.O_RDONLY | nofollow)
    pinned = private_directory / "mvmctl"
    try:
        mode = os.fstat(source_descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise ReproductionError("selected mvmctl must be a regular file, not a link")
        if not mode & 0o111:
            raise ReproductionError("selected mvmctl is not executable")
        target_descriptor = os.open(pinned, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        try:
            digest = hashlib.sha256()
            with os.fdopen(source_descriptor, "rb", closefd=False) as source_handle, \
                    os.fdopen(target_descriptor, "wb", closefd=False) as target_handle:
                for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    target_handle.write(chunk)
                target_handle.flush()
            # The private copy is owner-readable and executable, never writable
            # or privileged while it is invoked.
            os.fchmod(target_descriptor, 0o500)
        finally:
            os.close(target_descriptor)
    finally:
        os.close(source_descriptor)
    if digest.hexdigest() != expected or digest_file(pinned)[0] != expected:
        raise ReproductionError("selected mvmctl SHA-256 does not match")
    return pinned


def verify_output(directory):
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ReproductionError("layer output is not a directory")
    entries = {entry.name: entry for entry in directory.iterdir()}
    if set(entries) != OUTPUTS:
        raise ReproductionError("layer output must contain exactly three assets and asset-report.json")
    for entry in entries.values():
        if not stat.S_ISREG(entry.lstat().st_mode):
            raise ReproductionError(f"layer output is not a regular file: {entry.name}")

    try:
        report = json.loads(
            (directory / "asset-report.json").read_bytes(), object_pairs_hook=unique_object
        )
    except (UnicodeError, ValueError) as error:
        raise ReproductionError(f"invalid asset-report.json: {error}") from error
    if not isinstance(report, dict) or set(report) != {"assets"} or not isinstance(report["assets"], list):
        raise ReproductionError("asset-report.json must contain only an assets array")
    if len(report["assets"]) != len(ASSETS):
        raise ReproductionError("asset-report.json must declare exactly three assets")
    seen = set()
    for entry in report["assets"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ReproductionError("asset report entry must contain only path, sha256, and size")
        name = entry["path"]
        if not isinstance(name, str) or name not in ASSETS or name in seen:
            raise ReproductionError("asset report contains an unexpected or duplicate path")
        seen.add(name)
        if not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
            raise ReproductionError(f"invalid SHA-256 for {name}")
        if type(entry["size"]) is not int or entry["size"] <= 0:
            raise ReproductionError(f"invalid size for {name}")
        actual_digest, actual_size = digest_file(directory / name)
        if (actual_digest, actual_size) != (entry["sha256"], entry["size"]):
            raise ReproductionError(f"asset report does not match {name}")
    return {name: digest_file(directory / name) for name in OUTPUTS}


def same_bytes(first, second):
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            left_chunk = left.read(1024 * 1024)
            right_chunk = right.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def publish_noclobber(source, destination):
    """Atomically rename a directory without replacing any existing entry."""
    libc = ctypes.CDLL(None, use_errno=True)
    old = os.fsencode(source)
    new = os.fsencode(destination)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(-100, old, -100, new, 1)  # RENAME_NOREPLACE
    elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(-2, old, -2, new, 4)  # RENAME_EXCL
    else:
        raise ReproductionError("atomic no-clobber directory publication is unavailable")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def reproduce(source, binary, binary_sha256, output):
    source = Path(source)
    binary = Path(binary)
    output = Path(output)
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise ReproductionError("staged application tree must be a directory, not a link")
    if output.name in ("", ".", ".."):
        raise ReproductionError("output must name a new directory")
    parent = output.parent.resolve(strict=True)
    source = source.resolve(strict=True)
    if parent == source or source in parent.parents:
        raise ReproductionError("output must be outside the staged application tree")
    output = parent / output.name
    if output.exists() or output.is_symlink():
        raise ReproductionError("output already exists")
    with tempfile.TemporaryDirectory(prefix=".mvm-reproduce-a-", dir=parent) as first_temp, \
            tempfile.TemporaryDirectory(prefix=".mvm-reproduce-b-", dir=parent) as second_temp:
        pinned = pin_binary(binary, binary_sha256, Path(first_temp))
        first = Path(first_temp) / "layer"
        second = Path(second_temp) / "layer"
        for target in (first, second):
            command = [str(pinned), "image", "build-layer", "--source", str(source), "--output", str(target)]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode != 0:
                raise ReproductionError(f"mvmctl image build-layer failed with exit status {result.returncode}")
        first_hashes = verify_output(first)
        second_hashes = verify_output(second)
        if first_hashes != second_hashes:
            raise ReproductionError("independent application-layer builds differ")
        if any(not same_bytes(first / name, second / name) for name in OUTPUTS):
            raise ReproductionError("independent application-layer builds differ")
        publish_noclobber(first, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="complete, trusted, quiescent staged application tree")
    parser.add_argument("--mvmctl", required=True, type=Path, help="selected mvmctl binary")
    parser.add_argument("--mvmctl-sha256", required=True, help="independently supplied binary SHA-256")
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    args = parser.parse_args(argv)
    try:
        reproduce(args.source, args.mvmctl, args.mvmctl_sha256, args.output)
    except (OSError, ReproductionError) as error:
        parser.exit(1, f"reproduce-app-layer: {error}\n")


if __name__ == "__main__":
    main()
