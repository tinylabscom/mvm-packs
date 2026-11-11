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


RUNTIME_REFERENCE = re.compile(
    r"runtime/[a-z][a-z0-9-]*@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MAX_DEPENDENCIES = 16
MAX_LAYER_TAR = 2 * 1024**3
MAX_APPLICATION_ARCHIVE = 2 * 1024**3
POLICY_FILES = ("pack/group.toml", "pack/profile.toml")


def validate_runtime_layer(layer, reference=None):
    """Closed shape of `runtime_layer` (mvm specs/contracts/composable-pack-build.md; ADR 005).

    No kernel, no entrypoint, no publisher key of its own: the signed registry manifest
    binds the external layer archive by digest and size. Authored (pack.toml) and published forms share this check.
    """
    if not isinstance(layer, dict) or set(layer) != {
        "schema_version", "guest_arch", "dependencies", "archive"
    }:
        raise ValueError("runtime_layer must contain exactly schema_version/guest_arch/dependencies/archive")
    if type(layer["schema_version"]) is not int or layer["schema_version"] != 1:
        raise ValueError("runtime_layer schema_version must be integer 1")
    if layer["guest_arch"] not in ("x86_64", "aarch64"):
        raise ValueError("runtime_layer guest_arch must be x86_64 or aarch64")
    archive = layer["archive"]
    if not isinstance(archive, dict) or set(archive) != {"source", "archive_sha256", "archive_size"}:
        raise ValueError("runtime_layer archive must contain exactly source/archive_sha256/archive_size")
    validate_source(archive["source"])
    if not isinstance(archive["archive_sha256"], str) or not HEX64.fullmatch(archive["archive_sha256"]):
        raise ValueError("archive_sha256 must be 64 lowercase hex characters")
    if type(archive["archive_size"]) is not int or not 0 < archive["archive_size"] <= MAX_LAYER_TAR:
        raise ValueError("archive_size must be a positive integer of at most 2 GiB")
    pins = layer["dependencies"]
    if not isinstance(pins, list) or len(pins) > MAX_DEPENDENCIES:
        raise ValueError(f"runtime_layer dependencies must be a list of at most {MAX_DEPENDENCIES} pins")
    seen = set()
    for pin in pins:
        if not isinstance(pin, dict) or set(pin) != {"reference", "manifest_sha256"}:
            raise ValueError("each dependency must contain exactly reference and manifest_sha256")
        if not isinstance(pin["reference"], str) or not RUNTIME_REFERENCE.fullmatch(pin["reference"]):
            raise ValueError("dependency reference must be an exact runtime/name@major.minor.patch")
        if not isinstance(pin["manifest_sha256"], str) or not HEX64.fullmatch(pin["manifest_sha256"]):
            raise ValueError("dependency manifest_sha256 must be 64 lowercase hex characters")
        name = pin["reference"].split("@", 1)[0]
        if name in seen or (reference and name == reference.split("@", 1)[0]):
            raise ValueError(f"duplicate or self dependency on {name}")
        seen.add(name)


def validate_layer_files(files):
    """The signed inventory is only the policy: pack/group.toml and/or pack/profile.toml."""
    if not isinstance(files, list) or not 0 < len(files) <= len(POLICY_FILES):
        raise ValueError("runtime_layer files must list one or two policy files")
    paths = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ValueError("each file must contain exactly path, sha256 and size")
        if entry["path"] not in POLICY_FILES or entry["path"] in paths:
            raise ValueError(f"unexpected or duplicate file {entry['path']!r}")
        if not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
            raise ValueError("file sha256 must be 64 lowercase hex characters")
        if type(entry["size"]) is not int or entry["size"] <= 0:
            raise ValueError("file size must be a positive integer")
        paths.append(entry["path"])


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
    if type(bundle["archive_size"]) is not int or not 0 < bundle["archive_size"] <= MAX_APPLICATION_ARCHIVE:
        raise ValueError("bundle archive_size must be a positive integer of at most 2 GiB")
    if not isinstance(bundle["key_id"], str) or not HEX32.fullmatch(bundle["key_id"]):
        raise ValueError("bundle key_id must be 32 lowercase hex characters")


def runtime_layer_manifest_bytes(reference, description, layer, files):
    if not RUNTIME_REFERENCE.fullmatch(reference):
        raise ValueError("a runtime layer reference must be an exact runtime/name@version")
    validate_runtime_layer(layer, reference)
    validate_layer_files(files)
    return (json.dumps({
        "schema_version": 3,
        "kind": "runtime_layer",
        "reference": reference,
        "description": description,
        "runtime_layer": layer,
        "files": sorted(files, key=lambda entry: entry["path"]),
    }, indent=2, sort_keys=True) + "\n").encode()


def manifest_bytes(reference, description, application):
    validate_application(application)
    return (json.dumps({
        "schema_version": 2,
        "kind": "application",
        "reference": reference,
        "description": description,
        "application": application,
    }, indent=2, sort_keys=True) + "\n").encode()
