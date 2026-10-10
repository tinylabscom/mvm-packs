#!/usr/bin/env python3
"""Build and verify the separately signed official MVM revocation feed."""

import argparse
import json
import re
import runpy
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = runpy.run_path(str(ROOT / "scripts" / "build-revocations.py"))
RevocationError = LEGACY["RevocationError"]
read_source = LEGACY["read_source"]
validate_lists = LEGACY["validate_lists"]
utc = LEGACY["utc"]
timestamp = LEGACY["timestamp"]
check_advance = LEGACY["check_advance"]

IDENTITY = "https://github.com/tinylabscom/mvm-packs/.github/workflows/registry-pack-revocations.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
RELEASE_TAG = "registry-pack-revocations"
DOCUMENT_NAME = "revocations.json"
BUNDLE_NAME = "revocations.sigstore.json"
VALIDITY = timedelta(days=30)
MAX_BYTES = 1024 * 1024
NUMBERED_ASSET = re.compile(r"^revocations-([1-9][0-9]*)\.(json|sigstore\.json)$")


def parse_document(raw, now, *, allow_expired=False):
    if len(raw) > MAX_BYTES:
        raise RevocationError("revocation document exceeds 1 MiB")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RevocationError("revocation document repeats a JSON field")
            result[key] = value
        return result

    try:
        data = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RevocationError("revocation document is not valid JSON") from error
    required = {"schema_version", "sequence", "issued_at", "not_after", "revoked_identities", "revoked_manifests"}
    if not isinstance(data, dict) or set(data) != required:
        raise RevocationError("revocation document has missing or unknown fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RevocationError("unsupported revocation schema")
    if type(data["sequence"]) is not int or not 1 <= data["sequence"] <= 2**64 - 1:
        raise RevocationError("revocation sequence must be a positive u64")
    issued = utc(data["issued_at"])
    expires = utc(data["not_after"])
    if issued >= expires or expires - issued > VALIDITY:
        raise RevocationError("revocation validity window is invalid or too long")
    if issued > now:
        raise RevocationError("revocation document was issued in the future")
    if not allow_expired and expires <= now:
        raise RevocationError("revocation document has expired")
    identities, manifests = validate_lists(data)
    if identities != data["revoked_identities"] or manifests != data["revoked_manifests"]:
        raise RevocationError("revocation lists must be unique and sorted")
    return data


def verify_bundle(document, bundle):
    if any(not path.is_file() or path.is_symlink() for path in (document, bundle)):
        raise RevocationError("revocation document or signature bundle is missing or a symlink")
    if document.stat().st_size > MAX_BYTES or bundle.stat().st_size > MAX_BYTES:
        raise RevocationError("revocation document or signature bundle exceeds 1 MiB")
    try:
        result = subprocess.run(
            ["cosign", "verify-blob", str(document), "--bundle", str(bundle),
             "--certificate-identity", IDENTITY, "--certificate-oidc-issuer", ISSUER],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as error:
        raise RevocationError("cosign is required for revocation verification") from error
    if result.returncode != 0:
        raise RevocationError("revocation signature or release identity is invalid")


def inventory(names, *, allow_orphan=False):
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise RevocationError("release asset inventory must be a string array")
    if len(names) != len(set(names)):
        raise RevocationError("release asset inventory repeats a name")
    if any(name not in {DOCUMENT_NAME, BUNDLE_NAME} and name.startswith("revocations-") and NUMBERED_ASSET.fullmatch(name) is None for name in names):
        raise RevocationError("release has an unexpected numbered revocation asset")
    pairs = {}
    for name in names:
        match = NUMBERED_ASSET.fullmatch(name)
        if match:
            sequence = int(match.group(1))
            if sequence > 2**64 - 1:
                raise RevocationError("release asset sequence exceeds u64")
            pairs.setdefault(sequence, set()).add(match.group(2))
    if not pairs:
        raise RevocationError("release has no immutable revocation history")
    sequences = sorted(pairs)
    # The keys are already unique and sorted. Comparing the endpoints with the
    # count proves contiguity without constructing a range-sized list from
    # publisher-controlled sequence numbers.
    if sequences[0] != 1 or sequences[-1] != len(sequences):
        raise RevocationError("release sequence history has a gap")
    orphan = None
    for sequence, parts in pairs.items():
        if parts == {"json", "sigstore.json"}:
            continue
        expected_orphan_sequence = sequences[-2] + 1 if len(sequences) > 1 else 1
        if allow_orphan and sequence == sequences[-1] and sequence == expected_orphan_sequence and parts == {"json"}:
            orphan = sequence
            continue
        raise RevocationError("release has an incomplete or mismatched immutable sequence pair")
    return sequences, orphan


def _numbered_paths(directory, sequence):
    return directory / f"revocations-{sequence}.json", directory / f"revocations-{sequence}.sigstore.json"


def verify_history(directory, names, now, *, require_aliases=True):
    sequences, orphan = inventory(names)
    if orphan is not None:
        raise RevocationError("release history ends in an incomplete pair")
    previous = None
    newest = None
    for sequence in sequences:
        document, bundle = _numbered_paths(directory, sequence)
        verify_bundle(document, bundle)
        parsed = parse_document(document.read_bytes(), now, allow_expired=True)
        if parsed["sequence"] != sequence:
            raise RevocationError("numbered asset does not match its document sequence")
        if previous is not None:
            check_advance(parsed, previous)
        elif sequence != 1:
            raise RevocationError("revocation history does not start at sequence 1")
        previous = newest = parsed
    if require_aliases:
        if DOCUMENT_NAME not in names or BUNDLE_NAME not in names:
            raise RevocationError("current revocation aliases are missing")
        if (directory / DOCUMENT_NAME).read_bytes() != _numbered_paths(directory, sequences[-1])[0].read_bytes():
            raise RevocationError("current document alias does not match the newest verified sequence")
        if (directory / BUNDLE_NAME).read_bytes() != _numbered_paths(directory, sequences[-1])[1].read_bytes():
            raise RevocationError("current signature alias does not match the newest verified sequence")
    return newest


def _canonical_document(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
    encoded = _canonical_document(data)
    parse_document(encoded, now)
    return encoded


def recover_or_build(source, previous, orphan_bytes, expected_sequence, now):
    if orphan_bytes is None:
        return build_document(source, previous, now)
    if previous is None:
        raise RevocationError("an unsigned orphan cannot bootstrap a missing history")
    orphan = parse_document(orphan_bytes, now)
    if orphan["sequence"] != expected_sequence or expected_sequence != previous["sequence"] + 1:
        raise RevocationError("unsigned orphan sequence is not the next authenticated sequence")
    if (orphan["revoked_identities"], orphan["revoked_manifests"]) != source:
        raise RevocationError("unsigned orphan revocations do not exactly match reviewed source")
    if orphan_bytes != _canonical_document(orphan):
        raise RevocationError("unsigned orphan is not canonical JSON")
    return orphan_bytes


def _load_names(path):
    names = json.loads(path.read_text(encoding="utf-8"))
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "revocations.toml")
    parser.add_argument("--history", type=Path)
    parser.add_argument("--asset-names", type=Path)
    parser.add_argument("--prepare", type=Path, help="write the next candidate document")
    parser.add_argument("--build-initial", type=Path, help="write sequence 1 for an explicitly authorized first release")
    parser.add_argument("--verify-history", action="store_true")
    parser.add_argument("--restore-aliases", action="store_true")
    parser.add_argument("--document", type=Path, default=Path(DOCUMENT_NAME))
    parser.add_argument("--bundle", type=Path, default=Path(BUNDLE_NAME))
    parser.add_argument("--previous-document", type=Path)
    parser.add_argument("--previous-output", type=Path)
    parser.add_argument("--check-candidate", action="store_true")
    parser.add_argument("--now", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    now = utc(args.now) if args.now else datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if args.build_initial:
            if args.history or args.previous_document:
                raise RevocationError("initial feed cannot be built with existing history")
            args.build_initial.write_bytes(build_document(read_source(args.source), None, now))
            return
        if args.history is None or args.asset_names is None:
            if args.check_candidate:
                raise RevocationError("candidate verification requires its authenticated history")
            parser.error("--history and --asset-names are required")
        names = _load_names(args.asset_names)
        if args.verify_history or args.restore_aliases:
            if args.restore_aliases:
                sequences, orphan_sequence = inventory(names, allow_orphan=True)
                complete_names = [name for name in names if not (orphan_sequence and name == f"revocations-{orphan_sequence}.json")]
                if not any(NUMBERED_ASSET.fullmatch(name) and NUMBERED_ASSET.fullmatch(name).group(2) == "sigstore.json" for name in complete_names):
                    raise RevocationError("release has no complete verified sequence to restore aliases from")
                head = verify_history(args.history, complete_names, now, require_aliases=False)
            else:
                head = verify_history(args.history, names, now)
            document, bundle = _numbered_paths(args.history, head["sequence"])
            if args.restore_aliases:
                (args.history / DOCUMENT_NAME).write_bytes(document.read_bytes())
                (args.history / BUNDLE_NAME).write_bytes(bundle.read_bytes())
            print(head["sequence"])
            return
        if args.prepare:
            sequences, orphan_sequence = inventory(names, allow_orphan=True)
            if orphan_sequence is not None and (args.history / f"revocations-{orphan_sequence}.sigstore.json").exists():
                raise RevocationError("orphan sequence unexpectedly has a signature asset")
            complete_names = [name for name in names if not (orphan_sequence and name == f"revocations-{orphan_sequence}.json")]
            has_complete_pair = any(
                NUMBERED_ASSET.fullmatch(name)
                and NUMBERED_ASSET.fullmatch(name).group(2) == "sigstore.json"
                for name in complete_names
            )
            previous = verify_history(args.history, complete_names, now, require_aliases=False) if has_complete_pair else None
            if orphan_sequence is None and previous is None:
                raise RevocationError("existing release has no authenticated history")
            source = read_source(args.source)
            orphan_bytes = (args.history / f"revocations-{orphan_sequence}.json").read_bytes() if orphan_sequence else None
            if orphan_sequence and (previous is None or orphan_sequence != previous["sequence"] + 1):
                raise RevocationError("unsigned orphan is not immediately after verified history")
            args.prepare.write_bytes(recover_or_build(source, previous, orphan_bytes, orphan_sequence, now))
            if args.previous_output and previous is not None:
                previous_path, _ = _numbered_paths(args.history, previous["sequence"])
                args.previous_output.write_bytes(previous_path.read_bytes())
            if previous is not None:
                print(previous["sequence"])
            else:
                print("bootstrap")
            return
        if args.check_candidate:
            verify_bundle(args.document, args.bundle)
            current = parse_document(args.document.read_bytes(), now)
            source = read_source(args.source)
            if (current["revoked_identities"], current["revoked_manifests"]) != source:
                raise RevocationError("candidate revocations do not exactly match reviewed source")
            if args.previous_document:
                previous = parse_document(args.previous_document.read_bytes(), now, allow_expired=True)
                check_advance(current, previous)
            elif current["sequence"] != 1:
                raise RevocationError("bootstrap candidate must be sequence 1")
            print(current["sequence"])
            return
        parser.error("select --verify-history, --restore-aliases, --prepare, --build-initial, or --check-candidate")
    except (OSError, ValueError, RevocationError, subprocess.CalledProcessError) as error:
        sys.exit(f"build-dedicated-revocations: {error}")


if __name__ == "__main__":
    main()
