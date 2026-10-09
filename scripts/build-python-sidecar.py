#!/usr/bin/env python3
"""Derive the Python image sidecar from the pinned base and final ext4 bytes."""

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path


TEMPLATE_SHA256 = "ec7413b94e3decb890ef3fa959e527be5c1bf437e20fdf5ea80aa6b038987032"
GENERATOR_REV = "4e65b221744885e536ec91a3f2948cdc508dcb49"
EXPECTED_TEMPLATE = {
    "accessible": False, "agentBinary": "real", "builtAt": "",
    "entrypointKind": "command", "expectedBootMs": 300,
    "generatorRev": GENERATOR_REV, "hypervisor": "firecracker",
    "imageTag": "", "initSystem": "busybox", "name": "mvm-default-microvm",
    "overlayAware": True, "protocolVersion": 2,
    "rootlessEntrypoint": True, "runtimeLean": True, "sealed": True,
    "source": "built-local",
}


class SidecarError(Exception):
    """The proposed sidecar could not be bound to the pinned image."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise SidecarError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = helper("check-python-base-entrypoint.py", "base_for_python_sidecar")
runtime = helper("check-python-composed-runtime.py", "runtime_for_python_sidecar")
reproducer = helper("reproduce-app-layer.py", "reproducer_for_python_sidecar")


def pinned_template(path):
    path = Path(path)
    if path.name != "default-microvm-meta-x86_64.json" or not stat.S_ISREG(
        path.lstat().st_mode
    ):
        raise SidecarError("base sidecar must be a regular template asset")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != TEMPLATE_SHA256:
        raise SidecarError("base sidecar template digest differs from the reviewed release")
    try:
        metadata = json.loads(data, object_pairs_hook=reproducer.unique_object)
    except (UnicodeError, ValueError, reproducer.ReproductionError) as error:
        raise SidecarError("base sidecar template is invalid") from error
    if metadata != EXPECTED_TEMPLATE or not isinstance(metadata, dict):
        raise SidecarError("base sidecar template has unexpected claims")
    return metadata


def build(base_meta, base_rootfs, composed_rootfs, pack_source, output):
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise SidecarError("sidecar requires a new output file in an existing directory")
    metadata = pinned_template(base_meta)
    metadata["entrypointArgv"] = list(base.PIN.argv)
    metadata["libc"] = "glibc"
    body = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        with tempfile.TemporaryDirectory(prefix=".mvm-python-sidecar-", dir=output.parent) as directory:
            temporary = Path(directory) / "mvm-meta.json"
            temporary.write_bytes(body)
            base.verify(base_rootfs, pack_source, temporary)
            runtime.verify(composed_rootfs, temporary)
            os.link(temporary, output, follow_symlinks=False)
    except (OSError, ValueError, base.EntrypointError,
            runtime.RuntimeCheckError) as error:
        raise SidecarError("base entrypoint or composed runtime sidecar check failed") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-meta", required=True, type=Path)
    parser.add_argument("--base-rootfs", required=True, type=Path)
    parser.add_argument("--composed-rootfs", required=True, type=Path)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        build(args.base_meta, args.base_rootfs, args.composed_rootfs,
              args.pack_source, args.output)
    except (OSError, SidecarError) as error:
        parser.exit(1, f"build-python-sidecar: {error}\n")


if __name__ == "__main__":
    main()
