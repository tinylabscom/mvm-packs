import os
import shutil
import subprocess
import sys
import tempfile
import unittest
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
                         {"packages": ["bash"], "commands": []})
        for bad in ({}, {"packages": []}, {"extra": ["x"]}, {"packages": ["a", "a"]},
                    {"packages": ["../x"]}, {"commands": ["a b"]}, {"packages": "bash"},
                    {"packages": [f"p{i}" for i in range(65)]}, [], None):
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

    def test_a_root_without_a_nix_store_fails_closed(self):
        empty = Path(self.tmp.name) / "empty.ext4"
        subprocess.run([MKE2FS, "-q", "-t", "ext4", str(empty), "4M"], check=True, capture_output=True)
        with self.assertRaises(ValueError):
            rr.check_rootfs(empty, rr.validate_requirements({"packages": ["bash"]}))
