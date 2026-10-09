"""The unsigned candidate binds only independently checked, exact private inputs."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bind-image-candidate.py"
VERIFIER = '''#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys
a = sys.argv
manifest = pathlib.Path(a[a.index("--manifest") + 1])
artifacts = pathlib.Path(a[a.index("--artifacts") + 1])
names = [a[i + 1] for i, item in enumerate(a[:-1]) if item == "--artifact"]
entries = []
for name in names:
    data = (artifacts / name).read_bytes()
    entries.append({"role": "default_tenant_workload_kernel" if "vmlinux" in name else "default_tenant_workload_rootfs", "target": "x86_64", "name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
print(json.dumps({"verified": True, "scope": "selected-artifacts", "set_version": "0.2.4", "release_tag": "image-set/v0.2.4", "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "signer_key_id": "test-key", "unselected_artifacts_verified": False, "artifacts": entries}))
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BindImageCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "pack-sources" / "runtime" / "python"
        self.source.mkdir(parents=True)
        self.manifest = self.root / "image-set.json"
        self.manifest.write_bytes(b'{"schema_version":2}\n')
        self.bundle = self.root / "image-set.json.bundle"
        self.bundle.write_bytes(b"test bundle")
        self.artifacts = self.root / "base"
        self.artifacts.mkdir()
        self.names = (
            "default-microvm-vmlinux-x86_64",
            "default-microvm-rootfs-x86_64.ext4",
            "default-microvm-rootfs-x86_64.verity",
            "default-microvm-rootfs-x86_64.roothash",
        )
        for name in self.names:
            (self.artifacts / name).write_bytes(name.encode())
        self.layer = self.root / "layer"
        self.layer.mkdir()
        assets = []
        for name in ("rootfs.ext4", "rootfs.verity", "rootfs.roothash"):
            data = name.encode()
            (self.layer / name).write_bytes(data)
            assets.append({"path": name, "sha256": sha(data), "size": len(data)})
        (self.layer / "asset-report.json").write_text(json.dumps({"assets": assets}))
        self.binary = self.root / "mvmctl"
        self.binary.write_text(VERIFIER)
        self.binary.chmod(0o700)
        self.binary_sha = sha(self.binary.read_bytes())
        lines = [
            'version = "1.0.0"', 'description = "Python runtime"',
            '[image_build]', 'schema_version = 1', 'platform = "linux/x86_64"',
            '[image_build.base_set]', 'repository = "tinylabscom/mvm-images"',
            'release_tag = "image-set/v0.2.4"',
            f'manifest_sha256 = "{sha(self.manifest.read_bytes())}"',
            '[image_build.release]', 'repository = "tinylabscom/mvm-packs"',
            'tag = "pack-runtime-python-v1.0.0"',
        ]
        self.pack_source = self.source / "pack.toml"
        self.pack_source.write_text("\n".join(lines) + "\n")
        self.output = self.root / "candidate"

    def invoke(self, **overrides):
        values = {
            "pack-source": self.pack_source, "mvmctl": self.binary,
            "mvmctl-sha256": self.binary_sha, "manifest": self.manifest,
            "bundle": self.bundle, "artifacts": self.artifacts,
            "layer": self.layer, "output": self.output,
        }
        values.update(overrides)
        command = [sys.executable, str(SCRIPT)]
        for key, value in values.items():
            command += [f"--{key}", str(value)]
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_binds_exact_base_and_layer_bytes_without_official_status(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {file.name for file in self.output.iterdir()},
            {"candidate.json", "pack.toml", "image-set.json", "image-set.json.bundle", "base", "layer"},
        )
        candidate = json.loads((self.output / "candidate.json").read_text())
        self.assertEqual(candidate["kind"], "unsigned-image-candidate")
        self.assertEqual(candidate["base_set"]["manifest_sha256"], sha(self.manifest.read_bytes()))
        self.assertEqual(candidate["verifier_sha256"], self.binary_sha)
        self.assertEqual(candidate["base_artifacts"][self.names[0]]["sha256"], sha(self.names[0].encode()))
        self.assertEqual(candidate["application_layer"]["rootfs.ext4"]["size"], len("rootfs.ext4"))
        self.assertNotIn("official", candidate)
        second = self.root / "candidate-second"
        result = self.invoke(output=second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "candidate.json").read_bytes(),
                         (second / "candidate.json").read_bytes())

    def test_refuses_extra_missing_and_linked_files(self):
        for place, mutation in (("base", "extra"), ("base", "missing"),
                                ("base", "link"), ("layer", "extra"),
                                ("layer", "missing"), ("layer", "link")):
            with self.subTest(place=place, mutation=mutation):
                folder = self.artifacts if place == "base" else self.layer
                name = self.names[0] if place == "base" else "rootfs.ext4"
                path = folder / name
                original = path.read_bytes()
                extra = folder / "extra"
                if mutation == "extra":
                    extra.write_bytes(b"extra")
                elif mutation == "missing":
                    path.unlink()
                else:
                    path.unlink()
                    path.symlink_to(folder / (self.names[1] if place == "base" else "rootfs.verity"))
                try:
                    self.assertNotEqual(self.invoke().returncode, 0)
                    self.assertFalse(self.output.exists())
                finally:
                    extra.unlink(missing_ok=True)
                    path.unlink(missing_ok=True)
                    path.write_bytes(original)

    def test_refuses_tampering_bad_pin_and_existing_output(self):
        (self.layer / "rootfs.ext4").write_bytes(b"tampered")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.output.exists())
        (self.layer / "rootfs.ext4").write_bytes(b"rootfs.ext4")
        self.assertNotEqual(self.invoke(**{"mvmctl-sha256": "0" * 64}).returncode, 0)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        (self.output / "keep").write_text("owner")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual((self.output / "keep").read_text(), "owner")

    def test_refuses_incomplete_base_trust_evidence(self):
        self.bundle.unlink()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.output.exists())
        self.bundle.write_bytes(b"test bundle")
        self.manifest.write_bytes(b"wrong root")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_refuses_verifier_error_and_linked_trust_input(self):
        self.binary.write_text("#!/bin/sh\nexit 9\n")
        self.binary.chmod(0o700)
        self.assertNotEqual(self.invoke(**{"mvmctl-sha256": sha(self.binary.read_bytes())}).returncode, 0)
        self.assertFalse(self.output.exists())
        self.bundle.rename(self.root / "actual-bundle")
        self.bundle.symlink_to(self.root / "actual-bundle")
        self.assertNotEqual(self.invoke(**{"mvmctl-sha256": sha(self.binary.read_bytes())}).returncode, 0)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
