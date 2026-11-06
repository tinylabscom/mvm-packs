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
import threading

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
STORE_ENTRY = re.compile(r"[0-9a-z]{32}-(?P<name>[A-Za-z0-9+._-]+)\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9/._-]+\Z")
COMMAND_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")
KNOWN_DEBUGFS = ("/sbin/debugfs", "/usr/sbin/debugfs", "/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
MAX_OUTPUT = 4 << 20
MAX_LISTING = 20000
TIMEOUT = 60
ROOT_INODE = 2
MAX_ENTRIES = 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RELATIVE = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*\Z")


def validate_requirements(data):
    """Return {'packages': [...], 'commands': [...], 'binaries': [...]} or raise ValueError."""
    if not isinstance(data, dict) or not data or set(data) - {"packages", "commands", "binaries", "environment_policy"}:
        raise ValueError("requirements must be a table with packages, commands, binaries and/or environment_policy")
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
    policy = data.get("environment_policy")
    if policy is not None and (not isinstance(policy, dict) or not _plain_json(policy, depth=4)):
        raise ValueError("environment_policy must be a small table of strings, integers, booleans, lists and tables")
    result["environment_policy"] = policy
    if not (result["packages"] or result["commands"] or result["binaries"] or policy is not None):
        raise ValueError("requirements must name at least one package, command, binary or environment_policy")
    return result


def _plain_json(value, depth):
    """True for a small tree of dicts (string keys), lists, strings, ints and bools only."""
    import json
    if depth < 0:
        return False
    if isinstance(value, dict):
        ok = all(isinstance(k, str) and _plain_json(v, depth - 1) for k, v in value.items())
    elif isinstance(value, list):
        ok = all(_plain_json(v, depth - 1) for v in value)
    else:
        ok = isinstance(value, (str, bool)) or type(value) is int
    return ok and (depth < 4 or len(json.dumps(value)) <= 4096)


def needs_rootfs(requirements):
    """Whether any requirement must be checked against the root filesystem."""
    return bool(requirements["packages"] or requirements["commands"] or requirements["binaries"])


def _debugfs_path():
    return shutil.which("debugfs") or next((p for p in KNOWN_DEBUGFS if os.path.exists(p)), None)


def _run(image, command):
    """Run one read-only debugfs command with a real output cap and time limit."""
    debugfs = _debugfs_path()
    if debugfs is None:
        raise ValueError("debugfs (e2fsprogs) is required to check requirements and was not found")
    process = subprocess.Popen([debugfs, "-R", command, str(image)], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    timer = threading.Timer(TIMEOUT, process.kill)
    timer.start()
    try:
        data = process.stdout.read(MAX_OUTPUT + 1)
    finally:
        timer.cancel()
        process.kill()
        process.stdout.close()
        process.wait()
    if len(data) > MAX_OUTPUT:
        raise ValueError("debugfs output exceeded the size limit; refusing a partial listing")
    return data.decode("utf-8", "replace")


def _entries(image, inode):
    """List a directory by inode number: {name: (inode, mode)}. Names are never re-parsed."""
    found = {}
    for line in _run(image, f"ls -p <{inode}>").splitlines():
        parts = line.split("/")
        if len(parts) < 7 or parts[0] != "" or not parts[1].isdigit() or not re.fullmatch(r"[0-7]+", parts[2]):
            continue
        name = parts[5]
        if name in (".", "..", ""):
            continue
        if name in found:
            raise ValueError("directory listing has a duplicate name; refusing an ambiguous image")
        found[name] = (int(parts[1]), int(parts[2], 8))
        if len(found) > MAX_LISTING:
            raise ValueError("directory listing is too large; refusing a partial result")
    return found


def _walk(image, components):
    """Resolve path components from the root by inode; return (inode, mode) or None."""
    inode, mode = ROOT_INODE, 0o040000
    for component in components:
        if mode & 0o170000 != 0o040000:
            return None
        entry = _entries(image, inode).get(component)
        if entry is None:
            return None
        inode, mode = entry
    return inode, mode


def _store(image):
    """Return {full store name: (inode, package name)}; any odd store name refuses the image."""
    located = _walk(image, ["nix", "store"])
    if located is None:
        raise ValueError("root filesystem has no /nix/store; only Nix-store roots can be checked")
    store = {}
    for name, (inode, _) in _entries(image, located[0]).items():
        match = STORE_ENTRY.fullmatch(name)
        if match is None:
            raise ValueError("/nix/store has an entry whose name is not a plain Nix store name")
        store[name] = (inode, match.group("name"))
    if not store:
        raise ValueError("/nix/store is empty")
    return store


def _executable(found):
    if found is None:
        return False
    kind = found[1] & 0o170000
    return kind == 0o120000 or (kind == 0o100000 and found[1] & 0o111 != 0)


def _matches(package, name):
    return name == package or re.match(rf"{re.escape(package)}-\d", name) is not None


def _has_command(image, directory, command):
    return (directory is not None and directory[1] & 0o170000 == 0o040000
            and _executable(_entries(image, directory[0]).get(command)))


def check_rootfs(image, requirements):
    """Raise ValueError naming the first missing package, command or mismatched binary."""
    store = _store(image)
    for package in requirements["packages"]:
        if not any(_matches(package, name) for _, name in store.values()):
            raise ValueError(f"required package {package!r} is not in the root filesystem")
    for pin in requirements["binaries"]:
        _check_binary(image, store, pin)
    for command in requirements["commands"]:
        directories = [_walk(image, d.strip("/").split("/")) for d in COMMAND_DIRS]
        for inode, _ in store.values():
            directories.append(_entries(image, inode).get("bin"))
        if not any(_has_command(image, d, command) for d in directories):
            raise ValueError(f"required command {command!r} is not in the root filesystem")


def _file_in(image, start, package, path):
    """Inode of the regular file `path` under the store directory `start`, walked by inode."""
    entry = (start, 0o040000)
    for component in path.split("/"):
        entry = _entries(image, entry[0]).get(component) if entry[1] & 0o170000 == 0o040000 else None
        if entry is None:
            raise ValueError(f"{package!r} {path!r} is missing")
    if entry[1] & 0o170000 != 0o100000:
        raise ValueError(f"{package!r} {path!r} is not a regular file")
    return entry[0]


def _measure(image, inode):
    """(sha256, size) of a file dumped by inode from the image."""
    with tempfile.TemporaryDirectory(prefix="rootfs-binary-") as scratch:
        target = os.path.join(scratch, "file")
        if not SAFE_PATH.fullmatch(target):
            raise ValueError("temporary path contains characters debugfs could misread")
        _run(image, f"dump <{inode}> {target}")
        if not os.path.isfile(target):
            raise ValueError("debugfs did not produce the file")
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
        return digest.hexdigest(), os.path.getsize(target)


def _check_binary(image, store, pin):
    """The file must exist in every store directory of that package with exactly the pinned bytes."""
    package = pin["package"]
    matches = [inode for inode, name in store.values() if _matches(package, name)]
    if not matches:
        raise ValueError(f"binary package {package!r} is not in the root filesystem")
    for start in matches:
        sha256, size = _measure(image, _file_in(image, start, package, pin["path"]))
        if size != pin["size"]:
            raise ValueError(f"{package!r} {pin['path']!r} has an unpinned size")
        if sha256 != pin["sha256"]:
            raise ValueError(f"{package!r} {pin['path']!r} does not match its pinned SHA-256")


def store_packages(image):
    """Sorted plain package names (without hash) in /nix/store, for drafting a requirements list."""
    return sorted({re.split(r"-(?=\d)", name, maxsplit=1)[0] for _, name in _store(image).values()})


def derive_binary_pin(image, package, path):
    """Measure the one binary a pin should name. Refuses if the package is absent or ambiguous."""
    matches = [inode for inode, name in _store(image).values() if _matches(package, name)]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one store directory for {package!r}, found {len(matches)}")
    sha256, size = _measure(image, _file_in(image, matches[0], package, path))
    return {"package": package, "path": path, "sha256": sha256, "size": size}
