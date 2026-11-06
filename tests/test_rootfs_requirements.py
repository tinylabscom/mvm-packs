import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rootfs_requirements as rr  # noqa: E402

TOOLS = ("/opt/homebrew/opt/e2fsprogs/sbin", "/sbin", "/usr/sbin")
MKE2FS = shutil.which("mke2fs") or next((f"{d}/mke2fs" for d in TOOLS if os.path.exists(f"{d}/mke2fs")), None)
HAVE_TOOLS = bool(MKE2FS and rr._debugfs_path())
HASH = "a" * 32


class ValidateTests(unittest.TestCase):
    def test_valid_and_invalid_requirement_tables(self):
        self.assertEqual(rr.validate_requirements({"packages": ["bash"]}),
                         {"packages": ["bash"], "commands": [], "binaries": []})
        for bad in ({}, {"packages": []}, {"extra": ["x"]}, {"packages": ["a", "a"]},
                    {"packages": ["../x"]}, {"commands": ["a b"]}, {"packages": "bash"},
                    {"packages": [f"p{i}" for i in range(65)]}, [], None,
                    {"binaries": [{"package": "a", "path": "../x", "sha256": "a" * 64, "size": 1}]},
                    {"binaries": [{"package": "a", "path": "/x", "sha256": "a" * 64, "size": 1}]},
                    {"binaries": [{"package": "a", "path": "bin/x", "sha256": "A" * 64, "size": 1}]},
                    {"binaries": [{"package": "a", "path": "bin/x", "sha256": "a" * 64, "size": 0}]},
                    {"binaries": [{"package": "a", "path": "bin/x", "sha256": "a" * 64}]},
                    {"binaries": [{"package": "a", "path": "bin/x", "sha256": "a" * 64, "size": 1}] * 2}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rr.validate_requirements(bad)


@unittest.skipUnless(HAVE_TOOLS, "e2fsprogs (mke2fs, debugfs) not installed")
class RootfsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name) / "tree"
        for pkg, name, mode in ((f"{HASH}-bash-5.3p3", "bash", 0o755), (f"{HASH[:-1]}b-coreutils-9.8", "ls", 0o755),
                                (f"{HASH[:-1]}c-data-1.0", "readme", 0o644)):
            binary = root / "nix/store" / pkg / "bin" / name
            binary.parent.mkdir(parents=True)
            binary.write_text("x")
            binary.chmod(mode)
        (root / "bin").mkdir()
        (root / "bin/sh").symlink_to("/nix/store/%s-bash-5.3p3/bin/bash" % HASH)
        cls.image = Path(cls.tmp.name) / "root.ext4"
        subprocess.run([MKE2FS, "-q", "-t", "ext4", "-d", str(root), str(cls.image), "8M"], check=True,
                       capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_present_packages_and_commands_pass(self):
        rr.check_rootfs(self.image, rr.validate_requirements(
            {"packages": ["bash", "coreutils"], "commands": ["bash", "sh", "ls"]}))

    def test_missing_or_look_alike_requirements_are_refused(self):
        for bad in ({"packages": ["git"]}, {"packages": ["bas"]}, {"packages": ["coreutil"]},
                    {"commands": ["git"]}, {"commands": ["readme"]}):   # readme exists but is not executable
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rr.check_rootfs(self.image, rr.validate_requirements(bad))

    def pin(self, **changes):
        entry = {"package": "bash", "path": "bin/bash", "sha256": hashlib.sha256(b"x").hexdigest(), "size": 1}
        return rr.validate_requirements({"binaries": [entry | changes]})

    def test_a_pinned_binary_must_match_exactly(self):
        rr.check_rootfs(self.image, self.pin())
        for label, changes in {
            "other bytes": {"sha256": hashlib.sha256(b"y").hexdigest()},
            "other size": {"size": 2},
            "missing file": {"path": "bin/nope"},
            "missing package": {"package": "git"},
        }.items():
            with self.subTest(label), self.assertRaises(ValueError):
                rr.check_rootfs(self.image, self.pin(**changes))

    def test_a_swapped_binary_is_refused(self):
        """Same package name and path, different bytes: the case a name-only check would pass."""
        swapped = Path(self.tmp.name) / "swapped.ext4"
        tree = Path(self.tmp.name) / "tree2"
        binary = tree / "nix/store" / f"{HASH}-bash-5.3p3" / "bin" / "bash"
        binary.parent.mkdir(parents=True)
        binary.write_text("not the pinned binary")
        binary.chmod(0o755)
        subprocess.run([MKE2FS, "-q", "-t", "ext4", "-d", str(tree), str(swapped), "8M"], check=True,
                       capture_output=True)
        rr.check_rootfs(swapped, rr.validate_requirements({"packages": ["bash"], "commands": ["bash"]}))
        with self.assertRaises(ValueError):
            rr.check_rootfs(swapped, self.pin())

    def test_a_store_name_debugfs_could_misread_refuses_the_whole_image(self):
        for label, name in {"quote and space": f'{HASH}-evil" bin',
                            "backslash": f"{HASH}-evil\\x",
                            "not a store hash": "short-name-1.0"}.items():
            with self.subTest(label):
                tree = Path(self.tmp.name) / "tree-odd"
                shutil.rmtree(tree, ignore_errors=True)
                (tree / "nix/store" / f"{HASH}-bash-5.3p3" / "bin").mkdir(parents=True)
                (tree / "nix/store" / name / "bin").mkdir(parents=True)
                image = Path(self.tmp.name) / "odd.ext4"
                image.unlink(missing_ok=True)
                subprocess.run([MKE2FS, "-q", "-t", "ext4", "-d", str(tree), str(image), "8M"], check=True,
                               capture_output=True)
                with self.assertRaises(ValueError):
                    rr.check_rootfs(image, rr.validate_requirements({"packages": ["bash"]}))

    def test_truncated_debugfs_output_is_an_error_not_a_partial_result(self):
        with patch.object(rr, "MAX_OUTPUT", 64), self.assertRaises(ValueError):
            rr.check_rootfs(self.image, rr.validate_requirements({"packages": ["bash"]}))

    def test_an_oversized_listing_is_refused(self):
        with patch.object(rr, "MAX_LISTING", 1), self.assertRaises(ValueError):
            rr.check_rootfs(self.image, rr.validate_requirements({"packages": ["bash"]}))

    def test_a_root_without_a_nix_store_fails_closed(self):
        empty = Path(self.tmp.name) / "empty.ext4"
        subprocess.run([MKE2FS, "-q", "-t", "ext4", str(empty), "4M"], check=True, capture_output=True)
        with self.assertRaises(ValueError):
            rr.check_rootfs(empty, rr.validate_requirements({"packages": ["bash"]}))
