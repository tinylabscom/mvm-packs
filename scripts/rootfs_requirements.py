"""Check that an application's root filesystem embeds what its pack declares (ADR 003).

Reads the ext4 image with `debugfs -R` (read-only, no mount, nothing from the
image runs). The image must be the exact rootfs member already hash-checked
against the bundle manifest. debugfs output is untrusted text: it is only parsed
with fixed patterns and never echoed into messages.
"""

import os
import re
import shutil
import subprocess

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
STORE_ENTRY = re.compile(r"[0-9a-z]{32}-(?P<name>[^/\s]+)\Z")
COMMAND_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")
KNOWN_DEBUGFS = ("/sbin/debugfs", "/usr/sbin/debugfs", "/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
MAX_OUTPUT = 4 << 20
MAX_ENTRIES = 64


def validate_requirements(data):
    """Return {'packages': [...], 'commands': [...]} or raise ValueError."""
    if not isinstance(data, dict) or not data or set(data) - {"packages", "commands"}:
        raise ValueError("requirements must be a table with packages and/or commands")
    result = {}
    for key in ("packages", "commands"):
        values = data.get(key, [])
        if (not isinstance(values, list) or len(values) > MAX_ENTRIES or len(set(values)) != len(values)
                or not all(isinstance(v, str) and NAME.fullmatch(v) for v in values)):
            raise ValueError(f"requirements.{key} must be a list of at most {MAX_ENTRIES} unique plain names")
        result[key] = values
    if not (result["packages"] or result["commands"]):
        raise ValueError("requirements must name at least one package or command")
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
    for command in requirements["commands"]:
        candidates = [f"{d}/{command}" for d in COMMAND_DIRS] + [f"/nix/store/{full}/bin/{command}" for full, _ in store]
        if not any(_is_command(image, path) for path in candidates):
            raise ValueError(f"required command {command!r} is not in the root filesystem")
