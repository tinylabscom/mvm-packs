#!/usr/bin/env python3
"""Create a safe, unpublished policy-pack draft under pack-sources/."""

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
    (source / "pack").mkdir(parents=True)
    (source / "pack.toml").write_text(
        'version = "0.1.0"\ndescription = "Describe what this policy permits."\n', encoding="utf-8"
    )
    (source / "pack" / "group.toml").write_text(
        'description = "Describe what this policy permits."\nrequired = false\n\n'
        '[network]\nallow = []\n', encoding="utf-8"
    )
    (source / "pack" / "README.md").write_text(
        f"## Purpose\n\nDescribe when to use `{namespace}/{name}`.\n\n"
        "## Setup\n\nDescribe any credentials an operator may choose to configure; never include values.\n\n"
        "## Use\n\nDescribe a real use case. This policy pack is not a runnable image.\n",
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
