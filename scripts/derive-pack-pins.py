#!/usr/bin/env python3
"""Draft the pack.toml pins for a rebuilt application archive, and run every pre-sign check on it.

Usage:
    derive-pack-pins.py ARCHIVE.mvmpkg --key BUNDLE-PUBLISHER.pub --source https://.../ARCHIVE.mvmpkg \\
        [--binary PACKAGE:PATH ...] [--require-package NAME ...] [--require-command NAME ...]

It reads a local copy of the archive (download it yourself, into its own empty directory), measures
it, and runs the same checks the publisher runs before signing: structure, per-artifact hashes,
the Ed25519 manifest.sig against the key whose hash is the key_id, then the requirements you name.
It prints a draft [application] and [requirements] block for a person to review and paste. It
signs nothing, writes no file and does not decide what a pack should require: you name the
requirements, and they are verified against the real root filesystem, never invented.
"""

import argparse
import hashlib
import json
import runpy
import sys
import tarfile
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import rootfs_requirements  # noqa: E402
from application_manifest import validate_application  # noqa: E402


def measure(path):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def read_member(archive, name, limit):
    info = archive.getmember(name)
    if not info.isreg() or info.size > limit:
        raise ValueError(f"{name} is not a small regular file")
    return archive.extractfile(info).read()


def derive(archive_path, key_path, source, binaries, packages, commands):
    """Return the text of the draft pack.toml blocks; raise ValueError on any failed check."""
    sha256, size = measure(archive_path)
    key = Path(key_path).read_bytes()
    with tarfile.open(archive_path, "r:") as archive:
        manifest = json.loads(read_member(archive, "manifest.json", 1 << 20))
        rootfs_path = next((a["path"] for a in manifest["artifacts"] if a.get("role") == "rootfs"), None)
        if rootfs_path is None:
            raise ValueError("the bundle manifest lists no rootfs artifact")
        key_id, arch = manifest["key_id"], manifest["arch"]
        if len(key) != 32 or hashlib.sha256(key).hexdigest()[:32] != key_id:
            raise ValueError("the key file is not a 32-byte key whose hash matches the bundle key_id")
        application = {"schema_version": 1, "guest_arch": arch,
                       "bundle": {"source": source, "archive_sha256": sha256, "archive_size": size,
                                  "key_id": key_id}}
        validate_application(application)
        builder = runpy.run_path(str(SCRIPTS / "build-packs.py"))
        try:
            builder["inspect_bundle"](str(archive_path), application, key)
        except SystemExit as error:
            raise ValueError(str(error)) from error
        with tempfile.NamedTemporaryFile(prefix="rootfs-") as image:
            source_file = archive.extractfile(rootfs_path)
            while chunk := source_file.read(1 << 20):
                image.write(chunk)
            image.flush()
            pins = [rootfs_requirements.derive_binary_pin(image.name, package, path)
                    for package, _, path in (b.partition(":") for b in binaries)]
            requirements = rootfs_requirements.validate_requirements(
                {"packages": packages, "commands": commands, "binaries": pins}) if (
                    packages or commands or pins) else None
            if requirements:
                rootfs_requirements.check_rootfs(image.name, requirements)
            present = rootfs_requirements.store_packages(image.name)
    lines = ["[application]", "schema_version = 1", f'guest_arch = "{arch}"', "",
             "[application.bundle]", f'source = "{source}"', f'archive_sha256 = "{sha256}"',
             f"archive_size = {size}", f'key_id = "{key_id}"']
    if requirements:
        lines += ["", "[requirements]"]
        lines += [f"{key} = {json.dumps(requirements[key])}" for key in ("packages", "commands")
                  if requirements[key]]
        for pin in requirements["binaries"]:
            lines += ["", "[[requirements.binaries]]", f'package = "{pin["package"]}"',
                      f'path = "{pin["path"]}"', f'sha256 = "{pin["sha256"]}"', f'size = {pin["size"]}']
    lines += ["", "# Packages present in the root filesystem (for choosing requirements; not a recommendation):",
              "#   " + ", ".join(present)]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archive")
    parser.add_argument("--key", required=True, help="the 32-byte Ed25519 bundle public key file")
    parser.add_argument("--source", required=True, help="canonical HTTPS URL the archive will be released at")
    parser.add_argument("--binary", action="append", default=[], metavar="PACKAGE:PATH")
    parser.add_argument("--require-package", action="append", default=[])
    parser.add_argument("--require-command", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(derive(args.archive, args.key, args.source, args.binary,
                                args.require_package, args.require_command))
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        sys.exit(f"derive-pack-pins: {error}")


if __name__ == "__main__":
    main()
