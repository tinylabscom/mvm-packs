import hashlib
import io
import json
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from tests.test_ed25519 import sign  # noqa: E402
import rootfs_requirements as rr  # noqa: E402

tool = runpy.run_path(str(ROOT / "scripts" / "derive-pack-pins.py"))
derive = tool["derive"]

SECRET = bytes(range(32))
PUBLIC = sign(SECRET, b"")[0]
KEY_ID = hashlib.sha256(PUBLIC).hexdigest()[:32]
TOOLS = ("/opt/homebrew/opt/e2fsprogs/sbin", "/sbin", "/usr/sbin")
MKE2FS = shutil.which("mke2fs") or next((f"{d}/mke2fs" for d in TOOLS if os.path.exists(f"{d}/mke2fs")), None)
SOURCE = "https://bundles.example/test/app.mvmpkg"
HASH = "a" * 32


@unittest.skipUnless(MKE2FS and rr._debugfs_path(), "e2fsprogs (mke2fs, debugfs) not installed")
class DerivePinsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        tree = base / "tree"
        binary = tree / "nix/store" / f"{HASH}-tool-1.0" / "bin" / "tool"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"the application")
        binary.chmod(0o755)
        (tree / "nix/store" / f"{HASH[:-1]}b-helper-2.0" / "bin").mkdir(parents=True)
        image = base / "root.ext4"
        subprocess.run([MKE2FS, "-q", "-t", "ext4", "-d", str(tree), str(image), "8M"], check=True,
                       capture_output=True)
        rootfs = image.read_bytes()
        cls.rootfs_sha = hashlib.sha256(b"the application").hexdigest()
        files = {"artifacts/vmlinux": b"kernel", "artifacts/rootfs.ext4": rootfs}
        artifacts = [{"name": n.split("/")[1], "role": role, "path": n, "sha256": hashlib.sha256(files[n]).hexdigest(),
                      "size_bytes": len(files[n])}
                     for n, role in (("artifacts/vmlinux", "kernel"), ("artifacts/rootfs.ext4", "rootfs"))]
        manifest = json.dumps({"key_id": KEY_ID, "arch": "aarch64", "artifacts": artifacts}).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in {"manifest.json": manifest, "manifest.sig": sign(SECRET, manifest)[1], **files}.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        cls.archive = base / "app.mvmpkg"
        cls.archive.write_bytes(buffer.getvalue())
        cls.key = base / "app-bundle-publisher.pub"
        cls.key.write_bytes(PUBLIC)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_derive(self, binaries=(), packages=(), commands=(), key=None):
        return derive(self.archive, key or self.key, SOURCE, list(binaries), list(packages), list(commands))

    def test_prints_the_measured_pins_that_the_publisher_gate_then_accepts(self):
        text = self.run_derive(["tool:bin/tool"], ["tool"])
        self.assertIn(f'archive_sha256 = "{hashlib.sha256(self.archive.read_bytes()).hexdigest()}"', text)
        self.assertIn(f"archive_size = {self.archive.stat().st_size}", text)
        self.assertIn(f'key_id = "{KEY_ID}"', text)
        self.assertIn(f'sha256 = "{self.rootfs_sha}"', text)
        self.assertIn("size = 15", text)
        self.assertIn("#   helper, tool", text)

    def test_shows_a_small_file_verbatim_with_its_hash_and_refuses_bad_specs(self):
        text = derive(self.archive, self.key, SOURCE, [], [], [], None, ["tool:bin/tool"])
        self.assertIn("# ===== tool:bin/tool  (15 bytes, sha256 " + self.rootfs_sha, text)
        self.assertIn("the application", text)
        for bad in ("tool:../x", "tool:bin/nope", "git:bin/git", "relative/path", "/nix/store", "/etc/../x"):
            with self.subTest(bad), self.assertRaises(ValueError):
                derive(self.archive, self.key, SOURCE, [], [], [], None, [bad])

    def test_refuses_a_wrong_key_a_missing_requirement_and_an_ambiguous_or_absent_binary(self):
        other = Path(self.tmp.name) / "other.pub"
        other.write_bytes(bytes(range(1, 33)))
        for label, kwargs in {
            "wrong key": {"key": other},
            "missing package": {"packages": ["git"]},
            "missing command": {"commands": ["git"]},
            "absent binary": {"binaries": ["tool:bin/nope"]},
            "absent package": {"binaries": ["git:bin/git"]},
        }.items():
            with self.subTest(label), self.assertRaises(ValueError):
                self.run_derive(**kwargs)
