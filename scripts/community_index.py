"""Strict validator for community/index.json (schema_version 3, docs/community-index.md)."""

import re

from community_publishers import RESERVED, NAME, validate_reference

SHA = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?\Z")
PACK_FIELDS = {"namespace", "name", "description", "publisher", "versions"}
VERSION_FIELDS = {"version", "manifest_sha256", "tags", "guest_arch", "size_bytes"}
TAG = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")


def _key(version):
    core = version.split("-", 1)[0]
    return [int(part) for part in core.split(".")]


def validate_index(index):
    """Raise ValueError for anything the community index must not contain."""
    if not isinstance(index, dict) or set(index) != {"schema_version", "kind", "packs"}:
        raise ValueError("index must have exactly schema_version, kind and packs")
    if type(index["schema_version"]) is not int or index["schema_version"] != 3 or index["kind"] != "community":
        raise ValueError("index must be schema_version 3 with kind community")
    packs = index["packs"]
    if not isinstance(packs, list):
        raise ValueError("packs must be a list")
    order = []
    for pack in packs:
        if not isinstance(pack, dict) or set(pack) != PACK_FIELDS:
            raise ValueError("pack has missing or unknown fields")
        namespace, name = pack["namespace"], pack["name"]
        if not isinstance(namespace, str) or namespace in RESERVED:
            raise ValueError(f"{namespace!r} cannot be a community namespace")
        if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(pack["description"], str):
            raise ValueError(f"{namespace}/{name}: invalid name or description")
        publisher = pack["publisher"]
        if not isinstance(publisher, dict) or set(publisher) != {"repository", "workflow", "ref_pattern", "environment"}:
            raise ValueError(f"{namespace}/{name}: publisher must have exactly repository, workflow, ref_pattern, environment")
        validate_reference(namespace, dict(publisher, packs=[name]))
        versions = pack["versions"]
        if not isinstance(versions, list) or not versions:
            raise ValueError(f"{namespace}/{name}: versions must be a non-empty list")
        seen, tags = set(), set()
        for entry in versions:
            if not isinstance(entry, dict) or set(entry) - VERSION_FIELDS or {"version", "manifest_sha256"} - set(entry):
                raise ValueError(f"{namespace}/{name}: version has missing or unknown fields")
            version = entry["version"]
            if not isinstance(version, str) or not VERSION.fullmatch(version) or version in seen:
                raise ValueError(f"{namespace}/{name}: invalid or duplicate version {version!r}")
            seen.add(version)
            if not isinstance(entry["manifest_sha256"], str) or not SHA.fullmatch(entry["manifest_sha256"]):
                raise ValueError(f"{namespace}/{name}@{version}: manifest_sha256 must be 64 lowercase hex")
            if "guest_arch" in entry and entry["guest_arch"] not in ("x86_64", "aarch64"):
                raise ValueError(f"{namespace}/{name}@{version}: guest_arch must be x86_64 or aarch64")
            if "size_bytes" in entry and (type(entry["size_bytes"]) is not int or entry["size_bytes"] <= 0):
                raise ValueError(f"{namespace}/{name}@{version}: size_bytes must be a positive integer")
            for tag in entry.get("tags", []):
                if not isinstance(tag, str) or not TAG.fullmatch(tag) or tag in tags:
                    raise ValueError(f"{namespace}/{name}@{version}: invalid or repeated tag {tag!r}")
                tags.add(tag)
        listed = [entry["version"] for entry in versions]
        if listed != sorted(listed, key=_key, reverse=True):
            raise ValueError(f"{namespace}/{name}: versions must be newest first")
        order.append(f"{namespace}/{name}")
    if order != sorted(order) or len(set(order)) != len(order):
        raise ValueError("packs must be unique and sorted by namespace/name")
    return index
