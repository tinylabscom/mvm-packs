import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
REPRODUCE = ROOT / "scripts" / "reproduce-app-layer.py"
SPEC = importlib.util.spec_from_file_location("reproduce_app_layer", REPRODUCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FAKE_BUILDER = '''#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if args[:2] != ["image", "build-layer"]:
    sys.exit(2)
source = pathlib.Path(args[args.index("--source") + 1])
output = pathlib.Path(args[args.index("--output") + 1])
if not (source / "app").is_file():
    sys.exit(3)
state = pathlib.Path(os.environ["FAKE_BUILD_STATE"])
count = int(state.read_text()) if state.exists() else 0
state.write_text(str(count + 1))
mode = os.environ.get("FAKE_BUILD_MODE", "ok")
if mode == "command_failure":
    sys.exit(4)
output.mkdir()
assets = []
for name in ("rootfs.ext4", "rootfs.verity", "rootfs.roothash"):
    data = (name + ("changed" if mode == "mismatch" and count else "stable")).encode()
    (output / name).write_bytes(data)
    assets.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
if mode == "extra":
    (output / "undeclared").write_text("extra")
if mode == "missing":
    (output / "rootfs.verity").unlink()
if mode == "link":
    (output / "rootfs.verity").unlink()
    (output / "rootfs.verity").symlink_to("rootfs.ext4")
if mode == "malformed":
    (output / "asset-report.json").write_text("not json")
elif mode == "bad_shape":
    (output / "asset-report.json").write_text(json.dumps({"assets": assets, "official": True}))
elif mode == "bad_digest":
    assets[0]["sha256"] = "0" * 64
    (output / "asset-report.json").write_text(json.dumps({"assets": assets}))
elif mode == "duplicate_key":
    (output / "asset-report.json").write_text('{"assets": [], "assets": ' + json.dumps(assets) + '}')
else:
    (output / "asset-report.json").write_text(json.dumps({"assets": assets}))
'''


class ReproduceAppLayerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app").write_text("complete staged tree")
        self.binary = self.root / "mvmctl"
        self.binary.write_text(FAKE_BUILDER)
        self.binary.chmod(0o700)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.output = self.root / "published"
        self.state = self.root / "build-count"

    def invoke(self, mode="ok", digest=None):
        environment = os.environ.copy()
        environment["FAKE_BUILD_MODE"] = mode
        environment["FAKE_BUILD_STATE"] = str(self.state)
        return subprocess.run(
            [sys.executable, str(REPRODUCE), "--source", str(self.source),
             "--mvmctl", str(self.binary), "--mvmctl-sha256", digest or self.digest,
             "--output", str(self.output)],
            env=environment, capture_output=True, text=True, check=False,
        )

    def test_matching_independent_builds_publish_complete_output(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.read_text(), "2")
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {"rootfs.ext4", "rootfs.verity", "rootfs.roothash", "asset-report.json"},
        )

    def test_mismatched_builds_leave_no_output(self):
        result = self.invoke("mismatch")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("builds differ", result.stderr)
        self.assertFalse(self.output.exists())

    def test_malformed_extra_missing_link_and_bad_report_fail_closed(self):
        for mode in ("malformed", "extra", "missing", "link", "bad_shape", "bad_digest", "duplicate_key"):
            with self.subTest(mode=mode):
                self.state.unlink(missing_ok=True)
                result = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())

    def test_wrong_binary_digest_never_invokes_builder(self):
        result = self.invoke(digest="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 does not match", result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.output.exists())

    def test_symlinked_binary_is_rejected_before_invocation(self):
        actual = self.root / "actual-mvmctl"
        self.binary.rename(actual)
        self.binary.symlink_to(actual)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.output.exists())

    def test_replacing_selected_path_after_pinning_cannot_change_executable(self):
        original_run = subprocess.run
        replaced = False

        def replace_before_invocation(*args, **kwargs):
            nonlocal replaced
            if not replaced:
                self.binary.rename(self.root / "original-mvmctl")
                self.binary.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(9)\n")
                self.binary.chmod(0o700)
                replaced = True
            return original_run(*args, **kwargs)

        environment = {
            "FAKE_BUILD_MODE": "ok",
            "FAKE_BUILD_STATE": str(self.state),
        }
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(MODULE.subprocess, "run", side_effect=replace_before_invocation):
            MODULE.reproduce(self.source, self.binary, self.digest, self.output)
        self.assertTrue(replaced)
        self.assertEqual(self.state.read_text(), "2")
        self.assertTrue(self.output.is_dir())

    def test_existing_output_is_never_replaced(self):
        self.output.mkdir()
        marker = self.output / "owner-data"
        marker.write_text("keep")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "keep")
        self.assertFalse(self.state.exists())

    def test_atomic_publication_does_not_replace_late_destination(self):
        staging = self.root / "staging"
        staging.mkdir()
        self.output.mkdir()
        marker = self.output / "owner-data"
        marker.write_text("keep")
        with self.assertRaises(OSError):
            MODULE.publish_noclobber(staging, self.output)
        self.assertEqual(marker.read_text(), "keep")
        self.assertTrue(staging.is_dir())

    def test_builder_failure_leaves_no_output(self):
        result = self.invoke("command_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exit status 4", result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
