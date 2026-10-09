#!/usr/bin/env python3
"""Refuse signed Python evidence whose final ext4 lacks its measured glibc runtime."""

import argparse
import hashlib
import importlib.util
import re
import stat
import struct
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import NamedTuple


PYTHON_BIN = re.compile(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+/bin/[A-Za-z0-9+._-]+\Z")
STAT_HEADER = re.compile(r"^Inode:\s+\d+\s+Type:\s+(regular|symlink)\s+Mode:\s+([0-7]{4})", re.M)
STAT_SIZE = re.compile(r"^User:.*\bSize:\s+(\d+)\s*$", re.M)
FAST_LINK = re.compile(r'^Fast link dest: "([^"]+)"$', re.M)
MAX_FILE_SIZE = 32 << 20
BASE_INIT_SHA256 = "7cd9e304a82f7d0674d2caa3113b3dee733c1790100f8b48dbe0ef8222a4cf5e"


class FinalBootPin(NamedTuple):
    init_sha256: str
    marker_sha256: str
    argv: tuple[str, ...]


class RuntimeCheckError(Exception):
    """The signed image would misrepresent its Python runtime."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeCheckError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(rootfs, path, operation):
    if not path.startswith("/") or any(part in (".", "..") for part in PurePosixPath(path).parts):
        raise RuntimeCheckError("unsafe path in composed rootfs inspection")
    try:
        result = subprocess.run(
            ["debugfs", "-R", f"{operation} {path}", str(rootfs)],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise RuntimeCheckError("composed rootfs could not be inspected") from error
    if result.returncode != 0:
        raise RuntimeCheckError("composed rootfs inspection failed")
    return result.stdout


def inode(rootfs, path):
    output = inspect(rootfs, path, "stat")
    header, size = STAT_HEADER.search(output), STAT_SIZE.search(output)
    if header is None or size is None:
        raise RuntimeCheckError(f"composed rootfs omits a readable {path}")
    length = int(size.group(1))
    if not 1 <= length <= MAX_FILE_SIZE:
        raise RuntimeCheckError("composed runtime member has an invalid size")
    return header.group(1), int(header.group(2), 8), length, output


def dump(rootfs, path, length):
    with tempfile.TemporaryDirectory(prefix="mvm-python-ext4-", dir="/tmp") as temporary:
        destination = Path(temporary) / "member"
        try:
            result = subprocess.run(
                ["debugfs", "-R", f"dump {path} {destination}", str(rootfs)],
                capture_output=True, check=False, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeCheckError("composed runtime member could not be dumped") from error
        if (result.returncode != 0 or b"dump:" in result.stderr
                or not destination.is_file() or destination.stat().st_size != length):
            raise RuntimeCheckError("composed runtime member could not be read exactly")
        return destination.read_bytes()


def link_target(rootfs, path, length, output):
    fast = FAST_LINK.search(output)
    if fast is not None:
        try:
            value = fast.group(1).encode("ascii")
        except UnicodeError as error:
            raise RuntimeCheckError("composed runtime link is not ASCII") from error
    else:
        value = dump(rootfs, path, length)
    if len(value) != length or b"\0" in value:
        raise RuntimeCheckError("composed runtime link is malformed")
    try:
        return value.decode("ascii")
    except UnicodeError as error:
        raise RuntimeCheckError("composed runtime link is not ASCII") from error


def python_executable(rootfs):
    kind, _, length, output = inode(rootfs, "/bin/python3")
    if kind != "symlink":
        raise RuntimeCheckError("composed /bin/python3 is not the staged interpreter link")
    path = link_target(rootfs, "/bin/python3", length, output)
    if not PYTHON_BIN.fullmatch(path) or not path.endswith("/bin/python3"):
        raise RuntimeCheckError("composed Python link escapes its pinned store output")
    seen = set()
    for _ in range(4):
        if path in seen:
            raise RuntimeCheckError("composed Python links form a cycle")
        seen.add(path)
        kind, mode, length, output = inode(rootfs, path)
        if kind == "regular":
            if mode & 0o111 == 0:
                raise RuntimeCheckError("composed Python executable is not executable")
            return dump(rootfs, path, length)
        target = link_target(rootfs, path, length, output)
        if not re.fullmatch(r"[A-Za-z0-9+._-]+", target):
            raise RuntimeCheckError("composed Python link leaves its store bin directory")
        path = str(PurePosixPath(path).parent / target)
        if not PYTHON_BIN.fullmatch(path):
            raise RuntimeCheckError("composed Python link leaves its store output")
    raise RuntimeCheckError("composed Python link chain is too deep")


def locked_boot_pin():
    base = helper("check-python-base-entrypoint.py", "base_entrypoint_for_runtime_check")
    return FinalBootPin(BASE_INIT_SHA256, base.PIN.marker_sha256, base.PIN.argv)


def refuse_alternate_boot(rootfs):
    path = "/etc/mvm/boot"
    try:
        result = subprocess.run(
            ["debugfs", "-R", f"stat {path}", str(rootfs)],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise RuntimeCheckError("alternate boot path could not be inspected") from error
    if result.returncode != 0 or result.stdout.strip():
        raise RuntimeCheckError("composed rootfs carries an alternate boot path")
    if not result.stderr.strip().endswith(f"{path}: File not found by ext2_lookup"):
        raise RuntimeCheckError("alternate boot absence could not be established")


def verify_final_boot(rootfs, metadata, pin):
    if metadata["entrypointArgv"] != list(pin.argv):
        raise RuntimeCheckError("Python sidecar entrypoint argv differs from the pinned base")
    for path, expected, label in (
        ("/init", pin.init_sha256, "init"),
        ("/etc/mvm/entrypoint", pin.marker_sha256, "entrypoint"),
    ):
        kind, mode, length, _ = inode(rootfs, path)
        if kind != "regular" or mode & 0o111 == 0:
            raise RuntimeCheckError(f"composed {label} is not executable")
        if hashlib.sha256(dump(rootfs, path, length)).hexdigest() != expected:
            raise RuntimeCheckError(f"composed {label} differs from the pinned base")
    refuse_alternate_boot(rootfs)


def verify(rootfs, sidecar, boot_pin=None):
    rootfs, sidecar = Path(rootfs), Path(sidecar)
    if not stat.S_ISREG(rootfs.lstat().st_mode) or rootfs.stat().st_size == 0:
        raise RuntimeCheckError("composed rootfs must be a nonempty regular file")
    signer = helper("sign-composed-image.py", "signer_for_runtime_check")
    reproducer = helper("reproduce-app-layer.py", "reproducer_for_runtime_check")
    try:
        signer.check_boot_sidecar(sidecar, reproducer)
        metadata = signer.strict_json(sidecar, reproducer)
    except signer.SigningError as error:
        raise RuntimeCheckError("Python boot sidecar is invalid") from error
    if metadata["libc"] != "glibc":
        raise RuntimeCheckError("Python sidecar must declare the measured glibc ABI")
    verify_final_boot(rootfs, metadata, boot_pin if boot_pin is not None else locked_boot_pin())
    stage = helper("stage-python-closure.py", "stage_for_runtime_check")
    kind, _, length, output = inode(rootfs, "/lib64/ld-linux-x86-64.so.2")
    if kind != "symlink":
        raise RuntimeCheckError("composed rootfs lacks the staged glibc loader link")
    loader_path = link_target(rootfs, "/lib64/ld-linux-x86-64.so.2", length, output)
    if not stage.GLIBC_LOADER.fullmatch(loader_path):
        raise RuntimeCheckError("composed glibc loader link is not pinned to a Nix closure")
    kind, mode, length, _ = inode(rootfs, loader_path)
    if kind != "regular" or mode & 0o111 == 0:
        raise RuntimeCheckError("composed glibc loader is not a regular executable")
    loader = dump(rootfs, loader_path, length)
    if (len(loader) < 20 or loader[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", loader, 18)[0] != 62):
        raise RuntimeCheckError("composed glibc loader is not x86-64 ELF")
    executable = python_executable(rootfs)
    with tempfile.TemporaryDirectory(prefix="mvm-python-elf-", dir="/tmp") as temporary:
        binary = Path(temporary) / "python3"
        binary.write_bytes(executable)
        try:
            interpreter = stage.elf_interpreter(binary)
        except stage.StageError as error:
            raise RuntimeCheckError("composed Python ELF interpreter is invalid") from error
    if interpreter != loader_path:
        raise RuntimeCheckError("composed Python ELF uses a different glibc loader")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--mvm-meta", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        verify(args.rootfs, args.mvm_meta)
    except (OSError, ValueError, RuntimeCheckError) as error:
        parser.exit(1, f"check-python-composed-runtime: {error}\n")


if __name__ == "__main__":
    main()
