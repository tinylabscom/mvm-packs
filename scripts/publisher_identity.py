"""Exact publisher identities for the repository-rename transition."""

import hashlib
from datetime import datetime, timezone


CURRENT_IDENTITY = "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
FORMER_IDENTITY = "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main"
PUBLISHER_ISSUER = "https://token.actions.githubusercontent.com"
FORMER_CUTOFF = datetime(2026, 11, 6, tzinfo=timezone.utc)
LEGACY_NAMESPACES = frozenset({"agent", "runtime"})

# Only these previously published manifest bytes may retain the former signer.
HISTORICAL_MANIFEST_DIGESTS = frozenset({
    "c4be773ef57a0f4365730858e522207c5e609f9fda76f1499eab3d6b0c6293f5",
    "63f7c363966fe3bacb894e50be1e04e720ea6ac4e9a2d878fb2c811dc21bea7c",
    "043fe83720bd8dc25aa1c11c298993957a1b4ec23a71d0a7d2343b0b13024506",
    "1304b068122bc84fbae7c795727d9d7ccf3bf852cbb8309ab2e9d4903fdf2a1a",
    "f4049d71e7f18fcb23cb90f01898fe7af06b66daf958920416010a9aa8438272",
    "ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50",
    "e10d2c7f070e00a1b5d8c713568c0aebe608cc4e346c091a4cb25057ffd25bd3",
    "80903c11a95708dcf493d673bf76a99f3828a41a4e640550e19b76fd8affa229",
    "e9e27c4055186d2416af010804000410cbd54b86d530084aa706cb0bf79c344e",
})


def is_historical_manifest(reference, manifest_bytes):
    """Whether exact historical bytes may be checked under the former identity."""
    namespace = reference.split("/", 1)[0] if isinstance(reference, str) else ""
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    return namespace in LEGACY_NAMESPACES and digest in HISTORICAL_MANIFEST_DIGESTS


def accepts_former(reference, manifest_bytes, now=None):
    """Whether the bounded overlap still accepts a historical signer."""
    if now is None:
        now = datetime.now(timezone.utc)
    return now < FORMER_CUTOFF and is_historical_manifest(reference, manifest_bytes)
