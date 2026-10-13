#!/usr/bin/env python3
"""Write the local deploy record mvmctl needs to boot a staged signed rootfs.

`mvmctl run --deployment DIR` boots `DIR/rootfs.ext4` only when `DIR/deploy.json`
names its exact BLAKE3 and SHA-256 identity; the client rehashes the file before
boot and refuses a mismatch. The record is unsigned local input, not evidence.
The image identity it carries is the rootfs itself, because a staged pack image
has no separate deploy archive.
"""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


HEX64 = re.compile(r"[0-9a-f]{64}")
SCHEMA_VERSION = 2
WORKLOAD_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class RecordError(Exception):
    """The deployment directory cannot be described truthfully."""


def sha256_and_size(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def build_record(rootfs, blake3, workload_id, expected_sha256):
    if not HEX64.fullmatch(blake3):
        raise RecordError("BLAKE3 digest must be 64 lowercase hexadecimal characters")
    if not HEX64.fullmatch(expected_sha256):
        raise RecordError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    if not WORKLOAD_ID.fullmatch(workload_id):
        raise RecordError("workload id is invalid")
    if not stat.S_ISREG(rootfs.lstat().st_mode):
        raise RecordError("rootfs.ext4 must be a regular file, not a link")
    sha256, size = sha256_and_size(rootfs)
    if sha256 != expected_sha256:
        raise RecordError("rootfs.ext4 differs from the verified descriptor digest")
    if size <= 0:
        raise RecordError("rootfs.ext4 is empty")
    identity = {"blake3": blake3, "sha256": sha256, "size_bytes": size}
    return {
        "schema_version": SCHEMA_VERSION,
        "workload_id": workload_id,
        "ir_hash": sha256,
        "image": dict(identity),
        "boot_artifact": {"kind": "rootfs.ext4", **identity},
    }


def write(directory, blake3, workload_id, expected_sha256):
    directory = Path(directory)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise RecordError("deployment path must be a directory, not a link")
    record = build_record(directory / "rootfs.ext4", blake3, workload_id, expected_sha256)
    target = directory / "deploy.json"
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError as error:
        raise RecordError("deploy.json already exists") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", required=True, type=Path)
    parser.add_argument("--blake3", required=True)
    parser.add_argument("--sha256", required=True,
                        help="rootfs SHA-256 from the verified image descriptor")
    parser.add_argument("--workload-id", required=True)
    args = parser.parse_args(argv)
    try:
        write(args.deployment, args.blake3, args.workload_id, args.sha256)
    except (OSError, RecordError) as error:
        parser.exit(1, f"write-deployment-record: {error}\n")


if __name__ == "__main__":
    main()
