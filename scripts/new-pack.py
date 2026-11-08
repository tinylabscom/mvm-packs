#!/usr/bin/env python3
"""Create a safe, unpublished application-pack draft under pack-sources/."""

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"[a-z][a-z0-9-]*\Z")
# Clients trust this registry's signing identity by default for agent/ and runtime/
# (mvm ADR-055), and mvm/ is official, so submissions must not land there.
RESERVED = ("mvm", "agent", "runtime")


def create(root, namespace, name):
    if not NAME.fullmatch(namespace) or not NAME.fullmatch(name):
        raise ValueError("namespace and name must start with a lowercase letter and contain only a-z, 0-9, -")
    if namespace in RESERVED:
        raise ValueError(f"{namespace} is reserved for first-party packs; choose another namespace")
    source = root / "pack-sources" / namespace / name
    if source.is_symlink() or source.parent.is_symlink():
        raise ValueError("pack source paths must not be symlinks")
    if source.exists():
        raise FileExistsError(f"{source} already exists; choose a new name or bump its version")
    source.mkdir(parents=True)
    # A pack must embed its application binary in the .mvmpkg; a policy-only pack cannot be signed.
    # Fill in the archive pins (docs/application-packs.md); the draft fails to build until you do.
    (source / "pack.toml").write_text(
        'version = "0.1.0"\ndescription = "Describe the application this pack runs."\n\n'
        '[application]\nschema_version = 1\nguest_arch = "aarch64"\n\n'
        '[application.bundle]\nsource = "https://example.invalid/REPLACE.mvmpkg"\n'
        'archive_sha256 = "REPLACE"\narchive_size = 0\nkey_id = "REPLACE"\n',
        encoding="utf-8",
    )
    return source


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?")
    parser.add_argument("name", nargs="?")
    args = parser.parse_args()
    namespace = args.namespace or input("Namespace: ").strip()
    name = args.name or input("Name: ").strip()
    try:
        print(f"Draft created in {create(ROOT, namespace, name).relative_to(ROOT)}")
    except (ValueError, FileExistsError) as error:
        parser.exit(1, f"new pack: {error}\n")
