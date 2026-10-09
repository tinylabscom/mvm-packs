"""A composed pack rootfs must use both verified trees and reproduce exactly."""

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests.test_bind_image_candidate as candidate_tests


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compose-pack-image.py"
spec = importlib.util.spec_from_file_location("compose_pack_image", SCRIPT)
compose = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compose)


class MergeTreesTests(unittest.TestCase):
    def test_additive_application_tree_keeps_base_and_app_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            (base / "bin").mkdir(parents=True)
            (base / "bin" / "sh").write_bytes(b"base shell")
            (base / "app").mkdir()
            (app / "app").mkdir(parents=True)
            (app / "app" / "main.py").write_bytes(b"print('ok')\n")
            compose.merge_additive(app, base)
            self.assertEqual((base / "bin" / "sh").read_bytes(), b"base shell")
            self.assertEqual((base / "app" / "main.py").read_bytes(), b"print('ok')\n")

    def test_collision_refuses_without_overwriting_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            (base / "bin").mkdir(parents=True)
            (app / "bin").mkdir(parents=True)
            (base / "bin" / "sh").write_bytes(b"trusted base")
            (app / "bin" / "sh").write_bytes(b"replacement")
            with self.assertRaisesRegex(compose.CompositionError, "collides"):
                compose.merge_additive(app, base)
            self.assertEqual((base / "bin" / "sh").read_bytes(), b"trusted base")

    def test_additions_preserve_read_only_base_directory_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            (base / "nix" / "store").mkdir(parents=True)
            (app / "nix" / "store").mkdir(parents=True)
            (app / "nix" / "store" / "package").write_bytes(b"package")
            (base / "nix" / "store").chmod(0o555)
            compose.merge_additive(app, base)
            self.assertEqual((base / "nix" / "store" / "package").read_bytes(), b"package")
            self.assertEqual((base / "nix" / "store").stat().st_mode & 0o777, 0o555)
            (base / "nix" / "store").chmod(0o755)

    def test_symlinked_directory_cannot_redirect_the_merge(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            app.mkdir()
            (base / "app").symlink_to(root)
            (app / "app").mkdir()
            (app / "app" / "main.py").write_bytes(b"safe")
            with self.assertRaisesRegex(compose.CompositionError, "collides"):
                compose.merge_additive(app, base)
            self.assertFalse((root / "main.py").exists())

    def test_special_application_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            app.mkdir()
            os.mkfifo(app / "pipe")
            with self.assertRaisesRegex(compose.CompositionError, "regular file"):
                compose.merge_additive(app, base)

    def test_application_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            app.mkdir()
            (app / "escape").symlink_to(root)
            with self.assertRaisesRegex(compose.CompositionError, "symlink target"):
                compose.merge_additive(app, base)

    def test_nix_closure_links_are_preserved_without_following_host_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            (app / "nix" / "store" / "python" / "bin").mkdir(parents=True)
            (app / "nix" / "store" / "python" / "bin" / "python3.12").write_bytes(b"binary")
            (app / "nix" / "store" / "python" / "bin" / "python3").symlink_to("python3.12")
            (app / "bin").mkdir()
            (app / "bin" / "python3").symlink_to("/nix/store/python/bin/python3")
            compose.merge_additive(app, base)
            self.assertEqual(os.readlink(base / "nix" / "store" / "python" / "bin" / "python3"), "python3.12")
            self.assertEqual(os.readlink(base / "bin" / "python3"), "/nix/store/python/bin/python3")
            self.assertEqual((base / "nix" / "store" / "python" / "bin" / "python3.12").read_bytes(), b"binary")

    def test_relative_symlink_cannot_escape_the_guest_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            (app / "bin").mkdir(parents=True)
            (app / "bin" / "escape").symlink_to("../../../host-secret")
            with self.assertRaisesRegex(compose.CompositionError, "symlink target"):
                compose.merge_additive(app, base)
            self.assertFalse((base / "bin" / "escape").is_symlink())

    def test_absolute_nix_link_cannot_traverse_out_of_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            app = root / "app"
            base.mkdir()
            app.mkdir()
            (app / "escape").symlink_to("/nix/store/../../etc/passwd")
            with self.assertRaisesRegex(compose.CompositionError, "symlink target"):
                compose.merge_additive(app, base)
            self.assertFalse((base / "escape").is_symlink())


class SnapshotTests(unittest.TestCase):
    def test_snapshot_pins_exact_files_and_refuses_links(self):
        binder = compose.load_helper("bind-image-candidate.py", "bind_image_candidate_test")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            for name in compose.INPUTS - {"base", "layer"}:
                (source / name).write_bytes(name.encode())
            for name in ("base", "layer"):
                (source / name).mkdir()
                (source / name / "file").write_bytes(name.encode())
            target = root / "target"
            compose.snapshot_candidate(source, target, binder)
            (source / "base" / "file").write_bytes(b"changed")
            self.assertEqual((target / "base" / "file").read_bytes(), b"base")
            linked = root / "linked"
            (source / "base" / "file").unlink()
            (source / "base" / "file").symlink_to(source / "layer" / "file")
            with self.assertRaises(OSError):
                compose.snapshot_candidate(source, linked, binder)


@unittest.skipUnless(sys.platform.startswith("linux"), "debugfs extraction runs on Linux")
class RealExt4ExtractionTests(unittest.TestCase):
    def test_debugfs_extracts_real_ext4_bytes_without_host_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "bin").mkdir(parents=True)
            (source / "bin" / "sh").write_bytes(b"signed-base-bytes")
            (source / "outside").symlink_to(root / "should-not-be-created")
            image = root / "base.ext4"
            with image.open("wb") as handle:
                handle.truncate(32 * 1024 * 1024)
            subprocess.run(
                ["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(source), str(image)],
                check=True, capture_output=True,
            )
            extracted = root / "extracted"
            compose.extract_ext4(image, extracted)
            self.assertEqual((extracted / "bin" / "sh").read_bytes(), b"signed-base-bytes")
            self.assertTrue((extracted / "outside").is_symlink())
            self.assertFalse((root / "should-not-be-created").exists())


class CompareBuildsTests(unittest.TestCase):
    def test_identical_outputs_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            assets = []
            for name in ("rootfs.ext4", "rootfs.verity", "rootfs.roothash"):
                value = name.encode()
                (first / name).write_bytes(value)
                (second / name).write_bytes(value)
                assets.append({"path": name, "sha256": hashlib.sha256(value).hexdigest(), "size": len(value)})
            report = json.dumps({"assets": assets}).encode()
            (first / "asset-report.json").write_bytes(report)
            (second / "asset-report.json").write_bytes(report)
            compose.compare_builds(first, second)
            (second / "rootfs.ext4").write_bytes(b"different")
            with self.assertRaisesRegex(compose.CompositionError, "differ"):
                compose.compare_builds(first, second)


FAKE_MVMCTL = '''#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys
a = sys.argv
if a[1:4] == ["image", "boot", "verify"]:
    manifest = pathlib.Path(a[a.index("--manifest") + 1])
    artifacts = pathlib.Path(a[a.index("--artifacts") + 1])
    names = [a[i + 1] for i, item in enumerate(a[:-1]) if item == "--artifact"]
    entries = []
    for name in names:
        data = (artifacts / name).read_bytes()
        entries.append({"role": "default_tenant_workload_kernel" if "vmlinux" in name else "default_tenant_workload_rootfs", "target": "x86_64", "name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    print(json.dumps({"verified": True, "scope": "selected-artifacts", "set_version": "0.2.4", "release_tag": "image-set/v0.2.4", "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "signer_key_id": "test-key", "unselected_artifacts_verified": False, "artifacts": entries}))
elif a[1:3] == ["image", "build-layer"]:
    source = pathlib.Path(a[a.index("--source") + 1])
    output = pathlib.Path(a[a.index("--output") + 1])
    assert (source / "bin" / "sh").read_bytes() == b"trusted-base"
    assert (source / "app" / "main.py").read_bytes() == b"print('pack')"
    output.mkdir()
    payload = b"composed:" + (source / "bin" / "sh").read_bytes() + (source / "app" / "main.py").read_bytes()
    if os.getenv("FAKE_NONDETERMINISTIC") == "1":
        payload += source.parent.name.encode()
    values = {"rootfs.ext4": payload, "rootfs.verity": hashlib.sha256(payload).digest(), "rootfs.roothash": hashlib.sha256(payload).hexdigest().encode()}
    entries = []
    for name, data in values.items():
        (output / name).write_bytes(data)
        entries.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    (output / "asset-report.json").write_text(json.dumps({"assets": entries}))
else:
    raise SystemExit(2)
'''

FAKE_DEBUGFS = '''#!/usr/bin/env python3
import pathlib
import sys
command = sys.argv[sys.argv.index("-R") + 1]
assert command.startswith("rdump / ")
destination = pathlib.Path(command.removeprefix("rdump / "))
source = pathlib.Path(sys.argv[-1]).read_bytes()
if source.startswith(b"default-microvm-rootfs-"):
    (destination / "bin").mkdir()
    (destination / "bin" / "sh").write_bytes(b"trusted-base")
else:
    (destination / "app").mkdir()
    (destination / "app" / "main.py").write_bytes(b"print('pack')")
'''


class ComposeFlowTests(unittest.TestCase):
    def setUp(self):
        fixture = candidate_tests.BindImageCandidateTests(
            methodName="test_binds_exact_base_and_layer_bytes_without_official_status"
        )
        fixture.setUp()
        self.addCleanup(fixture.temporary.cleanup)
        self.fixture = fixture
        fixture.binary.write_text(FAKE_MVMCTL)
        fixture.binary.chmod(0o700)
        fixture.binary_sha = hashlib.sha256(fixture.binary.read_bytes()).hexdigest()
        result = fixture.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tools = fixture.root / "tools"
        self.tools.mkdir()
        debugfs = self.tools / "debugfs"
        debugfs.write_text(FAKE_DEBUGFS)
        debugfs.chmod(0o700)
        self.output = fixture.root / "composed"

    def invoke(self, extra_env=None, reference="runtime/python@1.0.0"):
        env = os.environ.copy()
        env["PATH"] = f"{self.tools}{os.pathsep}{env.get('PATH', '')}"
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--candidate", str(self.fixture.output),
             "--reference", reference,
             "--mvmctl", str(self.fixture.binary), "--mvmctl-sha256", self.fixture.binary_sha,
             "--output", str(self.output)],
            capture_output=True, text=True, check=False, env=env,
        )

    def test_composes_two_pinned_trees_twice_without_claiming_a_signed_image(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.output / "composition.json").read_text())
        self.assertEqual(report["kind"], "unsigned-composed-image")
        self.assertEqual(report["base_set"]["release_tag"], "image-set/v0.2.4")
        self.assertEqual(report["verifier_sha256"], self.fixture.binary_sha)
        self.assertTrue((self.output / "rootfs.ext4").read_bytes().startswith(b"composed:trusted-base"))
        self.assertNotIn("signature", report)

    def test_rejects_candidate_tamper_before_extracting(self):
        (self.fixture.output / "base" / self.fixture.names[1]).write_bytes(b"changed")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate digest record", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_nondeterministic_composed_bytes(self):
        result = self.invoke({"FAKE_NONDETERMINISTIC": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("builds differ", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_reference_and_base_pin(self):
        result = self.invoke(reference="runtime/other@1.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        report_path = self.fixture.output / "candidate.json"
        report = json.loads(report_path.read_text())
        report["base_set"]["manifest_sha256"] = "0" * 64
        report_path.write_text(json.dumps(report))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity differs", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_replaced(self):
        self.output.mkdir()
        (self.output / "owner").write_bytes(b"retained")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.output / "owner").read_bytes(), b"retained")


if __name__ == "__main__":
    unittest.main()
