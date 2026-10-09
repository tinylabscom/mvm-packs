"""Fail-closed checks around the selected signed base-set verifier."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-base-set.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("verify_base_set", SCRIPT)
verify_base_set = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_base_set)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class VerifyBaseSetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "pack-sources" / "runtime" / "python"
        self.source.mkdir(parents=True)
        self.manifest = self.root / "image-set.json"
        self.manifest.write_bytes(b'{"schema_version":2}\n')
        self.bundle = self.root / "image-set.json.bundle"
        self.bundle.write_bytes(b"signed bundle")
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.arch = "x86_64"
        self.expected = {
            f"default-microvm-vmlinux-{self.arch}": "default_tenant_workload_kernel",
            f"default-microvm-rootfs-{self.arch}.ext4": "default_tenant_workload_rootfs",
            f"default-microvm-rootfs-{self.arch}.verity": "default_tenant_workload_rootfs",
            f"default-microvm-rootfs-{self.arch}.roothash": "default_tenant_workload_rootfs",
        }
        for name in self.expected:
            (self.artifacts / name).write_bytes(name.encode())
        self.mvmctl = self.root / "mvmctl"
        self.mvmctl.write_bytes(b"pinned verifier")
        self.mvmctl.chmod(0o700)
        lines = [
            'version = "1.0.0"',
            'description = "Python runtime"',
            '[image_build]',
            'schema_version = 1',
            'platform = "linux/x86_64"',
            '[image_build.base_set]',
            'repository = "tinylabscom/mvm-images"',
            'release_tag = "image-set/v0.2.4"',
            f'manifest_sha256 = "{digest(self.manifest.read_bytes())}"',
            '[image_build.release]',
            'repository = "tinylabscom/mvm-packs"',
            'tag = "pack-runtime-python-v1.0.0"',
        ]
        self.pack_source = self.source / "pack.toml"
        self.pack_source.write_text("\n".join(lines) + "\n")
        self.report = {
            "verified": True,
            "scope": "selected-artifacts",
            "set_version": "0.2.4",
            "release_tag": "image-set/v0.2.4",
            "manifest_sha256": digest(self.manifest.read_bytes()),
            "signer_key_id": "trusted-release-identity",
            "unselected_artifacts_verified": False,
            "artifacts": [
                {
                    "role": role,
                    "target": self.arch,
                    "name": name,
                    "sha256": digest((self.artifacts / name).read_bytes()),
                    "size": (self.artifacts / name).stat().st_size,
                }
                for name, role in self.expected.items()
            ],
        }

    def call(self, report=None, returncode=0, stdout=None):
        result = subprocess.CompletedProcess(
            [], returncode,
            stdout=json.dumps(self.report if report is None else report) if stdout is None else stdout,
            stderr="",
        )
        def run(command, **_kwargs):
            self.invoked_binary_bytes = Path(command[0]).read_bytes()
            return result

        with patch.object(verify_base_set.subprocess, "run", side_effect=run) as invoked:
            verify_base_set.verify_base_set(
                self.pack_source,
                self.mvmctl,
                digest(self.mvmctl.read_bytes()),
                self.manifest,
                self.bundle,
                self.artifacts,
            )
        return invoked.call_args.args[0]

    def test_exact_selected_files_are_checked_without_lock_override(self):
        command = self.call()
        self.assertNotEqual(command[0], str(self.mvmctl.resolve()))
        self.assertEqual(Path(command[0]).name, "mvmctl")
        self.assertEqual(self.invoked_binary_bytes, self.mvmctl.read_bytes())
        self.assertEqual(command[1:4], ["image", "boot", "verify"])
        self.assertIn("--require-complete", command)
        self.assertIn("--json", command)
        self.assertNotIn("--lock", command)
        self.assertEqual(command.count("--artifact"), 4)
        self.assertEqual(set(command[command.index("--artifact") + 1::2]), set(self.expected))
        self.assertFalse((self.root / "packs").exists())

    def test_refuses_malformed_or_fake_positive_json(self):
        for mutation in (
            lambda r: r.update(verified=False),
            lambda r: r.update(scope="full"),
            lambda r: r.update(unselected_artifacts_verified=True),
            lambda r: r.update(artifacts=r["artifacts"][:-1]),
            lambda r: r["artifacts"][0].update(sha256="0" * 64),
            lambda r: r["artifacts"][0].update(role="builder_vm"),
            lambda r: r["artifacts"][0].update(target="aarch64"),
            lambda r: r["artifacts"][0].update(name="extra"),
            lambda r: r.update(extra="unexpected"),
        ):
            report = json.loads(json.dumps(self.report))
            mutation(report)
            with self.subTest(report=report), self.assertRaises(SystemExit):
                self.call(report)
        with self.assertRaises(SystemExit):
            self.call(stdout="not json")

    def test_refuses_wrong_root_or_tag(self):
        for field, value in (("release_tag", "image-set/v0.2.5"), ("manifest_sha256", "0" * 64)):
            report = json.loads(json.dumps(self.report))
            report[field] = value
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.call(report)

    def test_refuses_extra_or_symlinked_input(self):
        extra = self.artifacts / "unexpected"
        extra.write_bytes(b"extra")
        with self.assertRaises(SystemExit):
            self.call()
        extra.unlink()
        artifact = self.artifacts / next(iter(self.expected))
        artifact.unlink()
        artifact.symlink_to(self.manifest)
        with self.assertRaises(SystemExit):
            self.call()

    def test_refuses_wrong_verifier_pin_or_nonzero_verdict(self):
        with self.assertRaises(SystemExit):
            verify_base_set.verify_base_set(
                self.pack_source, self.mvmctl, "0" * 64,
                self.manifest, self.bundle, self.artifacts,
            )
        with self.assertRaises(SystemExit):
            self.call(returncode=1)

    def test_relative_verifier_cannot_be_shadowed_by_path(self):
        report = json.dumps(self.report)
        self.mvmctl.write_text(f"#!/bin/sh\nprintf '%s\\n' '{report}'\n")
        self.mvmctl.chmod(0o700)
        shadow = self.root / "malicious"
        shadow.mkdir()
        (shadow / "mvmctl").write_text("#!/bin/sh\nprintf 'malicious\\n'\n")
        (shadow / "mvmctl").chmod(0o700)
        original_directory = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ, {"PATH": f"{shadow}:{os.environ.get('PATH', '')}"}):
                verify_base_set.verify_base_set(
                    self.pack_source, Path("mvmctl"), digest(self.mvmctl.read_bytes()),
                    self.manifest, self.bundle, self.artifacts,
                )
        finally:
            os.chdir(original_directory)

    def test_replacing_selected_path_after_pinning_cannot_change_verifier(self):
        report = json.dumps(self.report)
        self.mvmctl.write_text(f"#!/bin/sh\nprintf '%s\\n' '{report}'\n")
        self.mvmctl.chmod(0o700)
        pinned_sha256 = digest(self.mvmctl.read_bytes())
        original_run = subprocess.run
        replaced = False

        def replace_before_invocation(command, **kwargs):
            nonlocal replaced
            if not replaced:
                self.mvmctl.rename(self.root / "original-verifier")
                self.mvmctl.write_text("#!/bin/sh\nexit 9\n")
                self.mvmctl.chmod(0o700)
                replaced = True
            return original_run(command, **kwargs)

        with patch.object(verify_base_set.subprocess, "run", side_effect=replace_before_invocation):
            verify_base_set.verify_base_set(
                self.pack_source, self.mvmctl, pinned_sha256,
                self.manifest, self.bundle, self.artifacts,
            )
        self.assertTrue(replaced)

    def test_refuses_source_outside_pack_sources(self):
        wrong = self.root / "other" / "runtime" / "python" / "pack.toml"
        wrong.parent.mkdir(parents=True)
        wrong.write_bytes(self.pack_source.read_bytes())
        with self.assertRaisesRegex(SystemExit, "pack-sources/namespace/name"):
            verify_base_set.verify_base_set(
                wrong, self.mvmctl, digest(self.mvmctl.read_bytes()),
                self.manifest, self.bundle, self.artifacts,
            )

    def test_undecodable_verifier_output_refuses(self):
        bad_utf8 = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        with patch.object(verify_base_set.subprocess, "run", side_effect=bad_utf8):
            with self.assertRaisesRegex(SystemExit, "could not complete"):
                verify_base_set.verify_base_set(
                    self.pack_source, self.mvmctl, digest(self.mvmctl.read_bytes()),
                    self.manifest, self.bundle, self.artifacts,
                )


if __name__ == "__main__":
    unittest.main()
