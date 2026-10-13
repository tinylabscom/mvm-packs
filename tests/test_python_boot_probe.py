"""The boot gate accepts only a working CPython run on the signed bytes."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recorder = load("write-deployment-record.py", "write_deployment_record")
probe = load("check-python-boot-probe.py", "check_python_boot_probe")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class DeploymentRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.deployment = Path(self.temp.name) / "deployment"
        self.deployment.mkdir()
        self.rootfs = b"signed rootfs bytes"
        (self.deployment / "rootfs.ext4").write_bytes(self.rootfs)
        self.blake3 = "b" * 64

    def test_record_names_the_exact_rootfs_identity(self):
        record = recorder.write(self.deployment, self.blake3, "runtime-python",
                                sha256(self.rootfs))
        written = json.loads((self.deployment / "deploy.json").read_text())
        self.assertEqual(written, record)
        self.assertEqual(written["schema_version"], 2)
        self.assertEqual(written["boot_artifact"], {
            "kind": "rootfs.ext4", "blake3": self.blake3,
            "sha256": sha256(self.rootfs), "size_bytes": len(self.rootfs),
        })
        self.assertEqual(set(written), {
            "schema_version", "workload_id", "ir_hash", "image", "boot_artifact"})

    def test_rootfs_that_differs_from_the_descriptor_refuses(self):
        with self.assertRaisesRegex(recorder.RecordError, "differs"):
            recorder.write(self.deployment, self.blake3, "runtime-python", "c" * 64)
        self.assertFalse((self.deployment / "deploy.json").exists())

    def test_malformed_digest_refuses(self):
        for blake3 in ("B" * 64, "b" * 63, "", "g" * 64):
            with self.subTest(blake3=blake3):
                with self.assertRaises(recorder.RecordError):
                    recorder.write(self.deployment, blake3, "runtime-python",
                                   sha256(self.rootfs))

    def test_existing_record_is_not_replaced(self):
        (self.deployment / "deploy.json").write_text("{}")
        with self.assertRaisesRegex(recorder.RecordError, "exists"):
            recorder.write(self.deployment, self.blake3, "runtime-python",
                           sha256(self.rootfs))
        self.assertEqual((self.deployment / "deploy.json").read_text(), "{}")

    def test_linked_rootfs_refuses(self):
        real = Path(self.temp.name) / "elsewhere.ext4"
        real.write_bytes(self.rootfs)
        (self.deployment / "rootfs.ext4").unlink()
        (self.deployment / "rootfs.ext4").symlink_to(real)
        with self.assertRaisesRegex(recorder.RecordError, "link"):
            recorder.write(self.deployment, self.blake3, "runtime-python",
                           sha256(self.rootfs))


class BootProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.deployment = root / "deployment"
        self.deployment.mkdir()
        assets = {}
        for role, name in probe.BOOTED_ASSETS.items():
            data = f"{name} bytes".encode()
            (self.deployment / name).write_bytes(data)
            assets[role] = {"name": name, "sha256": sha256(data), "size": len(data)}
        self.descriptor = root / "image-descriptor.json"
        self.descriptor.write_text(json.dumps({"assets": assets}))
        self.mvmctl = root / "mvmctl"
        self.mvmctl.write_bytes(b"client")
        self.stdout = root / "stdout"
        self.stderr = root / "stderr"
        self.stderr.write_bytes(b"")
        self.report = root / "boot-probe.json"

    def run_probe(self, stdout, exit_code):
        self.stdout.write_bytes(stdout)
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "check-python-boot-probe.py"),
             "--reference", "runtime/python@1.1.0",
             "--mvmctl", str(self.mvmctl), "--mvmctl-tag", "v0.24.0",
             "--descriptor", str(self.descriptor),
             "--deployment", str(self.deployment),
             "--command", json.dumps(["/bin/python3", "--version"]),
             "--exit-code", str(exit_code),
             "--stdout", str(self.stdout), "--stderr", str(self.stderr),
             "--report", str(self.report)],
            capture_output=True, text=True, check=False,
            env={**os.environ, "GITHUB_SHA": "a" * 40},
        )
        return result, json.loads(self.report.read_text())

    def test_working_interpreter_on_signed_bytes_passes(self):
        result, report = self.run_probe(b"Python 3.12.7\n", 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["python_version"], "Python 3.12.7")
        self.assertEqual(report["client"]["executable"]["sha256"], sha256(b"client"))
        self.assertEqual(set(report["booted_assets"]),
                         set(probe.BOOTED_ASSETS.values()))
        self.assertEqual(report["source"]["sha"], "a" * 40)

    def test_guest_refusal_is_recorded_and_fails(self):
        self.stderr.write_bytes(b"verb-trust policy requires a grant\n")
        result, report = self.run_probe(b"", 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["result"], "refused")
        self.assertIn("exited 1", report["reason"])
        self.assertIn("verb-trust", report["stderr"]["text"])

    def test_unexpected_output_fails_even_with_success_status(self):
        for stdout in (b"Python 3.11.9\n", b"Python 3.12.7", b"Python 3.12.7\n\n",
                       b"Python 3.12.7\nextra\n", b"python 3.12.7\n", b""):
            with self.subTest(stdout=stdout):
                self.report.unlink(missing_ok=True)
                result, report = self.run_probe(stdout, 0)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["result"], "refused")

    def test_booted_file_that_differs_from_the_descriptor_fails(self):
        (self.deployment / "rootfs.roothash").write_bytes(b"swapped")
        result, report = self.run_probe(b"Python 3.12.7\n", 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rootfs.roothash", report["reason"])

    def test_existing_report_is_not_overwritten(self):
        self.report.write_text("previous")
        self.stdout.write_bytes(b"Python 3.12.7\n")
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "check-python-boot-probe.py"),
             "--reference", "runtime/python@1.1.0",
             "--mvmctl", str(self.mvmctl), "--mvmctl-tag", "v0.24.0",
             "--descriptor", str(self.descriptor),
             "--deployment", str(self.deployment),
             "--command", "[]", "--exit-code", "0",
             "--stdout", str(self.stdout), "--stderr", str(self.stderr),
             "--report", str(self.report)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.report.read_text(), "previous")


if __name__ == "__main__":
    unittest.main()
