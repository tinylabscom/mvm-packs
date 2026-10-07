#!/usr/bin/env python3
"""Produce a short-lived, signed registry-pack revocation document."""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from publisher_identity import CURRENT_IDENTITY, PUBLISHER_ISSUER

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "revocations.toml"
DOCUMENT = ROOT / "packs" / "revocations.json"
BUNDLE = ROOT / "packs" / "revocations.sigstore.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_BYTES = 1024 * 1024
VALIDITY = timedelta(hours=36)


class RevocationError(ValueError):
    pass


def utc(value):
    if not isinstance(value, str):
        raise RevocationError("revocation timestamp must be a UTC string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RevocationError("revocation timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise RevocationError("revocation timestamp must be UTC")
    return parsed


def timestamp(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_lists(data):
    identities = data.get("revoked_identities", [])
    manifests = data.get("revoked_manifests", [])
    if not isinstance(identities, list) or not all(isinstance(item, str) for item in identities):
        raise RevocationError("revoked_identities must be a string array")
    if not isinstance(manifests, list) or not all(isinstance(item, str) for item in manifests):
        raise RevocationError("revoked_manifests must be a string array")
    if any(not item.strip() or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in identities):
        raise RevocationError("revoked identity is empty or contains a control character")
    if len(set(identities)) != len(identities):
        raise RevocationError("duplicate revoked identity")
    if any(not HEX64.fullmatch(item) for item in manifests):
        raise RevocationError("revoked manifest must be a lowercase SHA-256 digest")
    if len(set(manifests)) != len(manifests):
        raise RevocationError("duplicate revoked manifest")
    return sorted(identities), sorted(manifests)


def read_source(path=SOURCE):
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(data) != {"schema_version", "revoked_identities", "revoked_manifests"}:
        raise RevocationError("revocation source has missing or unknown fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RevocationError("revocation source schema_version must be 1")
    identities, manifests = validate_lists(data)
    return identities, manifests


def parse_document(raw, now, *, allow_expired=False):
    if len(raw) > MAX_BYTES:
        raise RevocationError("revocation document exceeds 1 MiB")
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise RevocationError("revocation document repeats a JSON field")
                result[key] = value
            return result

        data = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RevocationError("revocation document is not valid JSON") from error
    required = {"schema_version", "sequence", "issued_at", "not_after", "revoked_identities", "revoked_manifests"}
    if not isinstance(data, dict) or set(data) != required:
        raise RevocationError("revocation document has missing or unknown fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RevocationError("unsupported revocation schema")
    if type(data["sequence"]) is not int or data["sequence"] <= 0 or data["sequence"] > 2**64 - 1:
        raise RevocationError("revocation sequence must be a positive u64")
    issued = utc(data["issued_at"])
    expires = utc(data["not_after"])
    if issued >= expires or expires - issued > timedelta(hours=48):
        raise RevocationError("revocation validity window is invalid or too long")
    if issued > now:
        raise RevocationError("revocation document was issued in the future")
    if not allow_expired and expires <= now:
        raise RevocationError("revocation document has expired")
    validate_lists(data)
    return data


def verify_bundle(document, bundle):
    if not document.is_file() or not bundle.is_file() or document.is_symlink() or bundle.is_symlink():
        raise RevocationError("revocation document or signature bundle is missing or a symlink")
    try:
        result = subprocess.run(
            ["cosign", "verify-blob", str(document), "--bundle", str(bundle),
             "--certificate-identity", CURRENT_IDENTITY,
             "--certificate-oidc-issuer", PUBLISHER_ISSUER],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as error:
        raise RevocationError("cosign is required for revocation verification") from error
    if result.returncode != 0:
        raise RevocationError("revocation signature or publisher identity is invalid")


def build_document(source, previous, now):
    identities, manifests = source
    if previous is not None and (
        not set(previous["revoked_identities"]).issubset(identities)
        or not set(previous["revoked_manifests"]).issubset(manifests)
    ):
        raise RevocationError("revocation source cannot remove a published revocation")
    sequence = 1 if previous is None else previous["sequence"] + 1
    if sequence > 2**64 - 1:
        raise RevocationError("revocation sequence exhausted")
    data = {
        "schema_version": 1,
        "sequence": sequence,
        "issued_at": timestamp(now),
        "not_after": timestamp(now + VALIDITY),
        "revoked_identities": identities,
        "revoked_manifests": manifests,
    }
    encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    parse_document(encoded, now)
    return encoded


def check_advance(current, previous):
    if current["sequence"] != previous["sequence"] + 1:
        raise RevocationError("revocation feed did not advance by exactly one sequence")
    if (
        not set(previous["revoked_identities"]).issubset(current["revoked_identities"])
        or not set(previous["revoked_manifests"]).issubset(current["revoked_manifests"])
    ):
        raise RevocationError("published revocation set rolled back")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--document", type=Path, default=DOCUMENT)
    parser.add_argument("--bundle", type=Path, default=BUNDLE)
    parser.add_argument("--check-advance-from", type=Path)
    parser.add_argument("--check-advance-bundle", type=Path)
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if args.check_advance_from is not None or args.check_advance_bundle is not None:
            if args.check_advance_from is None or args.check_advance_bundle is None:
                raise RevocationError("both previous document and bundle are required")
            verify_bundle(args.check_advance_from, args.check_advance_bundle)
            previous = parse_document(args.check_advance_from.read_bytes(), now, allow_expired=True)
            verify_bundle(args.document, args.bundle)
            current = parse_document(args.document.read_bytes(), now)
            check_advance(current, previous)
            print(f"revocations: verified advancement to sequence {current['sequence']}")
            return
        source = read_source(args.source)
        previous = None
        if (args.document.exists() or args.bundle.exists()
                or args.document.is_symlink() or args.bundle.is_symlink()):
            verify_bundle(args.document, args.bundle)
            previous = parse_document(args.document.read_bytes(), now, allow_expired=True)
        encoded = build_document(source, previous, now)
        args.document.parent.mkdir(parents=True, exist_ok=True)
        args.document.write_bytes(encoded)
        args.bundle.unlink(missing_ok=True)
        subprocess.run(["cosign", "sign-blob", "--yes", "--bundle", str(args.bundle), str(args.document)], check=True)
        verify_bundle(args.document, args.bundle)
    except (OSError, RevocationError, subprocess.CalledProcessError) as error:
        sys.exit(f"build-revocations: {error}")
    print(f"revocations: signed sequence {previous['sequence'] + 1 if previous else 1}")


if __name__ == "__main__":
    main()
