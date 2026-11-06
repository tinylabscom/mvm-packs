"""Check that an application's root filesystem embeds what its pack declares (ADR 003).

Reads the ext4 image with `debugfs -R` (read-only, no mount, nothing from the
image runs). The image must be the exact rootfs member already hash-checked
against the bundle manifest. debugfs output is untrusted text: it is only parsed
with fixed patterns and never echoed into messages.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
STORE_ENTRY = re.compile(r"[0-9a-z]{32}-(?P<name>[^/\s]+)\Z")
COMMAND_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")
KNOWN_DEBUGFS = ("/sbin/debugfs", "/usr/sbin/debugfs", "/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
MAX_OUTPUT = 4 << 20
MAX_ENTRIES = 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RELATIVE = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*\Z")


def validate_requirements(data):
    """Return {'packages': [...], 'commands': [...], 'binaries': [...]} or raise ValueError."""
    if not isinstance(data, dict) or not data or set(data) - {"packages", "commands", "binaries"}:
        raise ValueError("requirements must be a table with packages, commands and/or binaries")
    result = {}
    for key in ("packages", "commands"):
        values = data.get(key, [])
        if (not isinstance(values, list) or len(values) > MAX_ENTRIES or len(set(values)) != len(values)
                or not all(isinstance(v, str) and NAME.fullmatch(v) for v in values)):
            raise ValueError(f"requirements.{key} must be a list of at most {MAX_ENTRIES} unique plain names")
        result[key] = values
    binaries = data.get("binaries", [])
    if not isinstance(binaries, list) or len(binaries) > MAX_ENTRIES:
        raise ValueError("requirements.binaries must be a list of tables")
    seen = set()
    for entry in binaries:
        if not isinstance(entry, dict) or set(entry) != {"package", "path", "sha256", "size"}:
            raise ValueError("each binary needs exactly package, path, sha256 and size")
        if (not isinstance(entry["package"], str) or not NAME.fullmatch(entry["package"])
                or not isinstance(entry["path"], str) or not RELATIVE.fullmatch(entry["path"])
                or ".." in entry["path"].split("/")
                or not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"])
                or type(entry["size"]) is not int or not 0 < entry["size"] <= 1 << 34):
            raise ValueError(f"invalid binary pin for {entry.get('package')!r}")
        if (entry["package"], entry["path"]) in seen:
            raise ValueError("duplicate binary pin")
        seen.add((entry["package"], entry["path"]))
    result["binaries"] = binaries
    if not (result["packages"] or result["commands"] or result["binaries"]):
        raise ValueError("requirements must name at least one package, command or binary")
    return result


def _debugfs_path():
    return shutil.which("debugfs") or next((p for p in KNOWN_DEBUGFS if os.path.exists(p)), None)


def _run(image, command):
    debugfs = _debugfs_path()
    if debugfs is None:
        raise ValueError("debugfs (e2fsprogs) is required to check requirements and was not found")
    try:
        done = subprocess.run([debugfs, "-R", command, str(image)], capture_output=True,
                              timeout=60, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError("debugfs timed out reading the root filesystem") from error
    return done.stdout[:MAX_OUTPUT].decode("utf-8", "replace")


def _store_names(image):
    names = []
    for line in _run(image, "ls -p /nix/store").splitlines():
        parts = line.split("/")
        if len(parts) >= 7:
            match = STORE_ENTRY.fullmatch(parts[5])
            if match:
                names.append((parts[5], match.group("name")))
    return names


def _is_command(image, path):
    match = re.search(r"Type:\s+(\w+)\s+Mode:\s+([0-7]+)", _run(image, f"stat {path}"))
    if not match:
        return False
    kind, mode = match.group(1), int(match.group(2), 8)
    return kind == "symlink" or (kind == "regular" and mode & 0o111 != 0)


def check_rootfs(image, requirements):
    """Raise ValueError naming the first missing package or command."""
    store = _store_names(image)
    if not store:
        raise ValueError("root filesystem has no /nix/store; only Nix-store roots can be checked")
    for package in requirements["packages"]:
        if not any(name == package or re.match(rf"{re.escape(package)}-\d", name) for _, name in store):
            raise ValueError(f"required package {package!r} is not in the root filesystem")
    for pin in requirements["binaries"]:
        _check_binary(image, store, pin)
    for command in requirements["commands"]:
        candidates = [f"{d}/{command}" for d in COMMAND_DIRS] + [f"/nix/store/{full}/bin/{command}" for full, _ in store]
        if not any(_is_command(image, path) for path in candidates):
            raise ValueError(f"required command {command!r} is not in the root filesystem")


def _check_binary(image, store, pin):
    """The file must exist in every store directory of that package with exactly the pinned bytes."""
    package = pin["package"]
    matches = [full for full, name in store if name == package or re.match(rf"{re.escape(package)}-\d", name)]
    if not matches:
        raise ValueError(f"binary package {package!r} is not in the root filesystem")
    for full in matches:
        with tempfile.TemporaryDirectory(prefix="rootfs-binary-") as scratch:
            target = os.path.join(scratch, "file")
            _run(image, f"dump /nix/store/{full}/{pin['path']} {target}")
            if not os.path.isfile(target) or os.path.getsize(target) != pin["size"]:
                raise ValueError(f"{package!r} {pin['path']!r} is missing or has an unpinned size")
            digest = hashlib.sha256()
            with open(target, "rb") as handle:
                while chunk := handle.read(1 << 20):
                    digest.update(chunk)
        if digest.hexdigest() != pin["sha256"]:
            raise ValueError(f"{package!r} {pin['path']!r} does not match its pinned SHA-256")
