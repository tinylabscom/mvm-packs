"""Owner approvals that must exist before the registry signs a component."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = {"reference", "archive_sha256", "approved_by", "date"}
HEX64 = re.compile(r"[0-9a-f]{64}")


def component_authorized(reference, archive_sha256, path=ROOT / "component-authorizations.toml"):
    """True only for an exact (reference, archive_sha256) approval; malformed content raises."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return False
    data = tomllib.loads(text)
    approved = data.get("approved", [])
    if set(data) - {"approved"} or not isinstance(approved, list):
        raise ValueError(f"{path}: only [[approved]] tables are allowed")
    seen = set()
    for entry in approved:
        if not isinstance(entry, dict) or set(entry) != KEYS or any(type(v) is not str for v in entry.values()):
            raise ValueError(f"{path}: each approval needs exactly {sorted(KEYS)} as strings")
        if not HEX64.fullmatch(entry["archive_sha256"]):
            raise ValueError(f"{path}: archive_sha256 must be 64 lowercase hex characters")
        pair = (entry["reference"], entry["archive_sha256"])
        if pair in seen:
            raise ValueError(f"{path}: duplicate approval for {pair[0]}")
        seen.add(pair)
    return (reference, archive_sha256) in seen
