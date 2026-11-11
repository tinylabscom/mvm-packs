"""Strict application descriptors shared by pack production and validation.

Descriptors bind downloadable bytes and an expected bundle key, not trust in
that key. Consumers must independently enforce bundle trust and revocation.
"""

import json
import ipaddress
import posixpath
import re
import tarfile
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
COMPONENT_REFERENCE = re.compile(
    r"[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*@"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
COMPONENT_NAME = re.compile(r"[a-z][a-z0-9_-]*\Z")
KERNEL_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MAX_COMPONENT_BYTES = 2 * 1024**3
COMPOSABLE_REFERENCE = re.compile(
    r"(?:runtime|tool)/[a-z0-9][a-z0-9_-]*@"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)


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


def validate_application_component(component):
    """Closed, non-bootable schema-1 application input; declarations do not grant capabilities."""
    if not isinstance(component, dict) or set(component) != {
        "schema_version", "guest_arch", "requirements", "archive", "entrypoints"
    }:
        raise ValueError("application_component has missing or unknown fields")
    if type(component["schema_version"]) is not int or component["schema_version"] != 1:
        raise ValueError("application_component schema_version must be integer 1")
    if type(component["guest_arch"]) is not str or component["guest_arch"] not in ("x86_64", "aarch64"):
        raise ValueError("application_component guest_arch must be x86_64 or aarch64")
    validate_component_archive(component["archive"])
    validate_component_requirements(component["requirements"])

    entrypoints = component["entrypoints"]
    if not isinstance(entrypoints, list) or len(entrypoints) > 16:
        raise ValueError("entrypoints must be a list of at most 16 named commands")
    names = set()
    for entry in entrypoints:
        if not isinstance(entry, dict) or set(entry) != {"name", "argv"}:
            raise ValueError("entrypoint must contain exactly name and argv")
        name, argv = entry["name"], entry["argv"]
        if not isinstance(name, str) or not COMPONENT_NAME.fullmatch(name) or name in names:
            raise ValueError("entrypoint name must be unique and canonical")
        names.add(name)
        if (not isinstance(argv, list) or not 0 < len(argv) <= 64
                or any(not isinstance(arg, str) or not arg or len(arg) > 4096 or "\x00" in arg for arg in argv)
                or not _absolute_path(argv[0])):
            raise ValueError("entrypoint argv must start with a canonical absolute executable")


def validate_component_archive(archive):
    if not isinstance(archive, dict) or set(archive) != {"source", "archive_sha256", "archive_size"}:
        raise ValueError("component archive has missing or unknown fields")
    validate_source(archive["source"])
    if not isinstance(archive["archive_sha256"], str) or not HEX64.fullmatch(archive["archive_sha256"]):
        raise ValueError("component archive_sha256 must be lowercase SHA-256")
    if type(archive["archive_size"]) is not int or not 0 < archive["archive_size"] <= MAX_COMPONENT_BYTES:
        raise ValueError("component archive_size must be positive and at most 2 GiB")


def validate_component_requirements(requirements):
    if not isinstance(requirements, dict) or set(requirements) not in (
        {"filesystem_abi", "libc", "minimum_kernel", "required_capabilities"},
        {"filesystem_abi", "libc", "loader", "minimum_kernel", "required_capabilities"},
    ):
        raise ValueError("component requirements have missing or unknown fields")
    if type(requirements["filesystem_abi"]) is not int or requirements["filesystem_abi"] != 1:
        raise ValueError("filesystem_abi must be integer 1")
    libc = requirements["libc"]
    loader = requirements.get("loader")
    if type(libc) is not str or libc not in ("static", "musl", "glibc"):
        raise ValueError("libc must be static, musl or glibc")
    if (libc == "static" and "loader" in requirements) or (
        libc != "static" and (not isinstance(loader, str) or not _absolute_path(loader))
    ):
        raise ValueError("loader must be absent for static or a canonical absolute path for dynamic libc")
    kernel = requirements["minimum_kernel"]
    if not isinstance(kernel, str) or not KERNEL_VERSION.fullmatch(kernel):
        raise ValueError("minimum_kernel must be major.minor.patch")
    capabilities = requirements["required_capabilities"]
    if (not isinstance(capabilities, list) or len(capabilities) > 16
            or any(not isinstance(name, str) or not COMPONENT_NAME.fullmatch(name) for name in capabilities)
            or len(set(capabilities)) != len(capabilities)):
        raise ValueError("required_capabilities must be at most 16 distinct canonical names")


def _absolute_path(path):
    return (path.startswith("/") and path != "/" and
            all(part not in ("", ".", "..") for part in path[1:].split("/")) and
            not any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in path))


def validate_composable_component(component, kind, reference=None):
    """Closed schema-1 runtime/tool payload; requirements are not grants."""
    if kind not in ("runtime_component", "tool_component"):
        raise ValueError("unsupported composable component kind")
    if not isinstance(component, dict) or set(component) != {
        "schema_version", "guest_arch", "requirements", "dependencies", "archive"
    }:
        raise ValueError(f"{kind} has missing or unknown fields")
    if type(component["schema_version"]) is not int or component["schema_version"] != 1:
        raise ValueError(f"{kind} schema_version must be integer 1")
    if type(component["guest_arch"]) is not str or component["guest_arch"] not in ("x86_64", "aarch64"):
        raise ValueError(f"{kind} guest_arch must be x86_64 or aarch64")
    validate_component_archive(component["archive"])
    validate_component_requirements(component["requirements"])
    pins = component["dependencies"]
    if not isinstance(pins, list) or len(pins) > MAX_DEPENDENCIES:
        raise ValueError(f"{kind} dependencies must be a list of at most {MAX_DEPENDENCIES} pins")
    seen = set()
    for pin in pins:
        if not isinstance(pin, dict) or set(pin) != {"reference", "manifest_sha256"}:
            raise ValueError("each dependency must contain exactly reference and manifest_sha256")
        dependency = pin["reference"]
        if not isinstance(dependency, str) or not COMPOSABLE_REFERENCE.fullmatch(dependency):
            raise ValueError("dependency reference must be exact runtime/name@version or tool/name@version")
        if not isinstance(pin["manifest_sha256"], str) or not HEX64.fullmatch(pin["manifest_sha256"]):
            raise ValueError("dependency manifest_sha256 must be 64 lowercase hex characters")
        name = dependency.split("@", 1)[0]
        if name in seen or (isinstance(reference, str) and name == reference.split("@", 1)[0]):
            raise ValueError(f"duplicate or self dependency on {name}")
        seen.add(name)


def composable_component_manifest_bytes(reference, description, kind, component, files):
    if kind not in ("runtime_component", "tool_component"):
        raise ValueError("unsupported composable component kind")
    if not isinstance(reference, str) or not COMPOSABLE_REFERENCE.fullmatch(reference) or (
        reference.split("/", 1)[0] != kind.removesuffix("_component")
    ):
        raise ValueError(f"{kind} reference must be exact {kind.removesuffix('_component')}/name@major.minor.patch")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"{kind} description must be nonempty")
    validate_composable_component(component, kind, reference)
    validate_layer_files(files)
    encoded = (json.dumps({
        "schema_version": 4,
        "kind": kind,
        "reference": reference,
        "description": description,
        kind: component,
        "files": sorted(files, key=lambda entry: entry["path"]),
    }, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > 1 << 20:
        raise ValueError(f"{kind} descriptor exceeds 1 MiB")
    return encoded


def application_component_manifest_bytes(reference, description, component, files):
    if not isinstance(reference, str) or not COMPONENT_REFERENCE.fullmatch(reference):
        raise ValueError("application component reference must be exact ns/name@major.minor.patch")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("application component description must be nonempty")
    validate_application_component(component)
    validate_layer_files(files)
    encoded = (json.dumps({
        "schema_version": 3,
        "kind": "application_component",
        "reference": reference,
        "description": description,
        "application_component": component,
        "files": sorted(files, key=lambda entry: entry["path"]),
    }, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > 1 << 20:
        raise ValueError("application component descriptor exceeds 1 MiB")
    return encoded


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


def inspect_component_payload(path, kind, max_bytes=2 * 1024**3):
    """Read a component tar without extracting; return {"files", "bytes"} or raise ValueError."""
    if kind not in ("application_component", "runtime_component", "tool_component"):
        raise ValueError("unsupported component kind")
    files = total = 0
    links, names, dirs = {}, set(), set()  # links: symlink name -> resolved target parts

    def resolve(base, target):
        stack, pending = list(base), [p for p in target.split("/")][::-1]
        for _ in range(1000):
            if not pending:
                return stack
            part = pending.pop()
            if part in ("", "."):
                continue
            if part == "..":
                if not stack:
                    return None
                stack.pop()
                continue
            stack.append(part)
            if "/".join(stack) in links:
                stack = list(links["/".join(stack)])
        return None

    try:
        with tarfile.open(path, "r:") as archive:
            for member in archive:
                name = member.name.rstrip("/")
                parts = name.split("/")
                if name.startswith("/") or ".." in parts:
                    raise ValueError(f"{name}: absolute or parent-relative path")
                if kind == "application_component" and not (name.startswith("srv/app/") or (member.isdir() and name == "srv/app")):
                    raise ValueError(f"{name}: application payload must live under srv/app/")
                if member.mode & 0o6000:
                    raise ValueError(f"{name}: setuid/setgid bit")
                if name in names:
                    raise ValueError(f"{name}: duplicate member name")
                if any("/".join(parts[:i]) in links for i in range(1, len(parts))):
                    raise ValueError(f"{name}: written through an earlier symlink")
                names.add(name)
                if member.issym():
                    if name in dirs:
                        raise ValueError(f"{name}: symlink replaces a directory")
                    target = resolve(parts[:-1], member.linkname) if not member.linkname.startswith("/") else None
                    if target is None:
                        raise ValueError(f"{name}: symlink escapes the payload root")
                    if kind == "application_component" and target[:2] != ["srv", "app"]:
                        raise ValueError(f"{name}: symlink leaves srv/app/")
                    links[name] = target
                    continue
                dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
                if member.isdir():
                    dirs.add(name)
                elif member.isfile():
                    files += 1
                    total += member.size
                    if total > max_bytes:
                        raise ValueError("payload exceeds the size cap")
                else:
                    raise ValueError(f"{name}: only files, directories and symlinks are allowed")
    except tarfile.TarError as error:
        raise ValueError(f"unreadable tar: {error}") from error
    if files == 0 or total == 0:
        raise ValueError("payload has no file content")
    return {"files": files, "bytes": total}
