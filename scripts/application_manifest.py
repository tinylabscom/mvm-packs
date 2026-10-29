"""Strict application descriptors shared by pack production and validation.

Descriptors bind downloadable bytes and an expected bundle key, not trust in
that key. Consumers must independently enforce bundle trust and revocation.
"""

import json
import ipaddress
import re
from urllib.parse import unquote, urlsplit


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def unique_object(pairs):
    """Do not let duplicate JSON keys disguise the signed descriptor shape."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def validate_authority(authority, https=False):
    """Reject credentials and ambiguous authorities before any download."""
    try:
        parsed = urlsplit("https://" + authority + "/")
        port = parsed.port
    except ValueError as error:
        raise ValueError("bundle source has an invalid authority") from error
    if (
        not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.netloc != authority
        or authority != authority.lower() or "%" in authority
        or any(character in authority for character in "/?#\\")
        or authority.endswith(":")
        or port is not None and not 1 <= port <= 65535
    ):
        raise ValueError("bundle source must have an explicit authority without credentials")
    host = parsed.hostname
    if ":" in host:
        canonical_host = "[" + str(ipaddress.IPv6Address(host)) + "]"
    else:
        canonical_host = host
        # URL parsers normalize alternative IPv4 spellings. Never publish a
        # source whose host changes when the consumer parses it.
        last_label = host.rstrip(".").rsplit(".", 1)[-1]
        if last_label.isdigit() or last_label.startswith("0x"):
            try:
                canonical_host = str(ipaddress.IPv4Address(host))
            except ipaddress.AddressValueError as error:
                raise ValueError("bundle source has a noncanonical IPv4 host") from error
        elif not re.fullmatch(r"[a-z0-9._-]+", host):
            raise ValueError("bundle source has an invalid hostname")
    if https:
        expected = canonical_host + (f":{port}" if port is not None and port != 443 else "")
        if authority != expected:
            raise ValueError("HTTPS source authority must already be canonical")


def validate_source(source):
    """Mirror the application's canonical URL/OCI contract, not general OCI."""
    if not isinstance(source, str) or not source or any(
        ord(character) <= 32 or ord(character) >= 127 for character in source
    ) or "\\" in source:
        raise ValueError("bundle source must be a canonical HTTPS or OCI string")
    if source.startswith("oci://"):
        match = re.fullmatch(r"oci://([^/]+)/([a-z0-9/._-]+)@sha256:([0-9a-f]{64})", source)
        if match is None:
            raise ValueError("OCI source must name a canonical repository and SHA-256 digest")
        authority, repository, _ = match.groups()
        validate_authority(authority)
        if not ("." in authority or ":" in authority or authority == "localhost"):
            raise ValueError("OCI source must include an explicit registry")
        if any(part in ("", ".", "..") for part in repository.split("/")):
            raise ValueError("OCI source repository contains an unsafe component")
        if authority == "docker.io" and "/" not in repository:
            raise ValueError("Docker Hub source must include its canonical library namespace")
        return
    try:
        parsed = urlsplit(source)
    except ValueError as error:
        raise ValueError("bundle source is not a valid HTTPS URL") from error
    if (
        not source.startswith("https://") or parsed.scheme != "https"
        or "?" in source or "#" in source or not parsed.path.startswith("/")
        or any(character in parsed.path for character in '<>"`{}')
        or any(unquote(part).lower() in (".", "..") for part in parsed.path.split("/"))
    ):
        raise ValueError("bundle source must already be a canonical HTTPS URL without query or fragment")
    validate_authority(parsed.netloc, https=True)


def validate_application(application):
    """Raise ValueError for any unsupported application descriptor field."""
    if not isinstance(application, dict) or set(application) != {
        "schema_version", "guest_arch", "bundle"
    }:
        raise ValueError("application must contain exactly schema_version/guest_arch/bundle")
    if type(application["schema_version"]) is not int or application["schema_version"] != 1:
        raise ValueError("application schema_version must be integer 1")
    if application["guest_arch"] not in ("x86_64", "aarch64"):
        raise ValueError("application guest_arch must be x86_64 or aarch64")
    bundle = application["bundle"]
    if not isinstance(bundle, dict) or set(bundle) != {
        "source", "archive_sha256", "archive_size", "key_id"
    }:
        raise ValueError("application bundle has missing or unknown fields")
    validate_source(bundle["source"])
    if not isinstance(bundle["archive_sha256"], str) or not HEX64.fullmatch(bundle["archive_sha256"]):
        raise ValueError("bundle archive_sha256 must be 64 lowercase hex characters")
    if type(bundle["archive_size"]) is not int or not 0 < bundle["archive_size"] <= 2**64 - 1:
        raise ValueError("bundle archive_size must be a positive u64 integer")
    if not isinstance(bundle["key_id"], str) or not HEX32.fullmatch(bundle["key_id"]):
        raise ValueError("bundle key_id must be 32 lowercase hex characters")


def manifest_bytes(reference, description, application):
    validate_application(application)
    return (json.dumps({
        "schema_version": 2,
        "kind": "application",
        "reference": reference,
        "description": description,
        "application": application,
    }, indent=2, sort_keys=True) + "\n").encode()
