"""The builder VM exports only a fully reproduced unsigned Python image."""

import hashlib
import importlib.util
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-python-image.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("build_python_image", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class BuildPythonImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "mvmctl"
        self.binary.write_bytes(b"verified released client")
        self.binary.chmod(0o755)
        self.pin = self.root / "mvmctl.sha256"
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.pin.write_text(self.digest + "\n")
        self.manifest = self.root / "image-set.json"
        self.manifest.write_bytes(b"signed root")
        self.bundle = self.root / "image-set.json.bundle"
        self.bundle.write_bytes(b"signature bundle")
        self.artifacts = self.root / "base"
        self.artifacts.mkdir()
        for name in (
            "default-microvm-vmlinux-x86_64",
            "default-microvm-rootfs-x86_64.ext4",
            "default-microvm-rootfs-x86_64.verity",
            "default-microvm-rootfs-x86_64.roothash",
        ):
            (self.artifacts / name).write_bytes(b"base asset")
        intent = tomllib.loads(builder.PYTHON_SOURCE.read_text())["image_build"]["base_set"]
        self.lock = self.root / "images.lock"
        self.lock.write_text(
            f'schema_version = 2\nrepository = "{intent["repository"]}"\n'
            f'[image_set]\nrepository = "{intent["repository"]}"\n'
            f'release_tag = "{intent["release_tag"]}"\n'
            f'manifest_sha256 = "{intent["manifest_sha256"]}"\n'
        )
        self.output = self.root / "exported"

    def run_builder(self):
        return builder.build(
            builder.PYTHON_SOURCE, self.binary, self.pin, self.manifest,
            self.bundle, self.artifacts, self.lock, self.output,
        )

    def fake_stage(self, target):
        target.mkdir()
        (target / "bin").mkdir()

    def fake_layer(self, source, binary, digest, target):
        self.assertEqual(digest, self.digest)
        self.assertEqual(binary, self.binary)
        self.assertTrue((source / "bin").is_dir())
        target.mkdir()
        (target / "rootfs.ext4").write_bytes(b"layer")

    def fake_candidate(self, pack_source, binary, digest, manifest, bundle,
                       artifacts, layer, target):
        self.assertEqual(pack_source, builder.PYTHON_SOURCE)
        self.assertEqual(digest, self.digest)
        self.assertTrue((layer / "rootfs.ext4").is_file())
        target.mkdir()
        (target / "candidate.json").write_bytes(b"candidate")

    def fake_composition(self, candidate, reference, binary, digest, target):
        self.assertEqual(reference, "runtime/python@1.1.0")
        self.assertEqual(digest, self.digest)
        self.assertTrue((candidate / "candidate.json").is_file())
        target.mkdir()
        (target / "composition.json").write_bytes(b"composition")
        (target / "rootfs.ext4").write_bytes(b"reproduced rootfs")
        (target / "rootfs.verity").write_bytes(b"verity")
        (target / "rootfs.roothash").write_bytes(b"roothash")
        (target / "asset-report.json").write_bytes(b"report")

    def fake_publish(self, staged, destination):
        self.assertFalse(destination.exists())
        staged.rename(destination)

    def test_exports_only_after_all_four_producer_gates_succeed(self):
        with mock.patch.object(builder.sys, "platform", "linux"), \
                mock.patch.object(builder.stage, "build_and_stage", self.fake_stage), \
                mock.patch.object(builder.reproducer, "reproduce", self.fake_layer), \
                mock.patch.object(builder.binder, "bind", self.fake_candidate), \
                mock.patch.object(builder.composer, "compose", self.fake_composition), \
                mock.patch.object(builder.signer, "validate_snapshot") as validate, \
                mock.patch.object(builder.reproducer, "publish_noclobber", self.fake_publish):
            self.run_builder()
        validate.assert_called_once()
        self.assertEqual(
            {entry.name for entry in self.output.iterdir()},
            {"candidate.json", "composition"},
        )
        self.assertEqual(
            (self.output / "composition" / "rootfs.ext4").read_bytes(),
            b"reproduced rootfs",
        )

    def test_refuses_wrong_client_digest_before_nix(self):
        self.pin.write_text("0" * 64 + "\n")
        with mock.patch.object(builder.sys, "platform", "linux"), \
                mock.patch.object(builder.stage, "build_and_stage") as stage:
            with self.assertRaisesRegex(builder.BuildError, "client digest"):
                self.run_builder()
        stage.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_refuses_advanced_mvm_base_lock_before_nix(self):
        self.lock.write_text(self.lock.read_text().replace("image-set/v0.2.4", "image-set/v0.2.5"))
        with mock.patch.object(builder.sys, "platform", "linux"), \
                mock.patch.object(builder.stage, "build_and_stage") as stage:
            with self.assertRaisesRegex(builder.BuildError, "current images.lock"):
                self.run_builder()
        stage.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_each_failed_gate_leaves_no_export(self):
        gates = (
            ("stage", "build_and_stage"),
            ("reproducer", "reproduce"),
            ("binder", "bind"),
            ("composer", "compose"),
        )
        for module_name, function in gates:
            with self.subTest(gate=function):
                module = getattr(builder, module_name)
                with mock.patch.object(builder.sys, "platform", "linux"), \
                        mock.patch.object(builder.stage, "build_and_stage", self.fake_stage), \
                        mock.patch.object(builder.reproducer, "reproduce", self.fake_layer), \
                        mock.patch.object(builder.binder, "bind", self.fake_candidate), \
                        mock.patch.object(builder.composer, "compose", self.fake_composition), \
                        mock.patch.object(builder.signer, "validate_snapshot"), \
                        mock.patch.object(module, function, side_effect=ValueError("gate refused")):
                    with self.assertRaisesRegex(builder.BuildError, "gate refused"):
                        self.run_builder()
                self.assertFalse(self.output.exists())

    def test_snapshot_verification_failure_leaves_no_export(self):
        with mock.patch.object(builder.sys, "platform", "linux"), \
                mock.patch.object(builder.stage, "build_and_stage", self.fake_stage), \
                mock.patch.object(builder.reproducer, "reproduce", self.fake_layer), \
                mock.patch.object(builder.binder, "bind", self.fake_candidate), \
                mock.patch.object(builder.composer, "compose", self.fake_composition), \
                mock.patch.object(builder.signer, "validate_snapshot", side_effect=ValueError("digest mismatch")):
            with self.assertRaisesRegex(builder.BuildError, "digest mismatch"):
                self.run_builder()
        self.assertFalse(self.output.exists())

    def test_refuses_host_execution_or_existing_output(self):
        with mock.patch.object(builder.sys, "platform", "darwin"):
            with self.assertRaisesRegex(builder.BuildError, "Linux builder VM"):
                self.run_builder()
        self.output.mkdir()
        with mock.patch.object(builder.sys, "platform", "linux"):
            with self.assertRaisesRegex(builder.BuildError, "new directory"):
                self.run_builder()


if __name__ == "__main__":
    unittest.main()
