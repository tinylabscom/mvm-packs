"""The publisher refuses sidecars that misstate the pinned base entrypoint."""

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "check_python_base_entrypoint", ROOT / "scripts/check-python-base-entrypoint.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PythonBaseEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rootfs = self.root / "default-microvm-rootfs-x86_64.ext4"
        self.rootfs.write_bytes(b"verified base rootfs")
        self.source = self.root / "pack.toml"
        self.sidecar = self.root / "mvm-meta.json"
        self.base = {
            "repository": "tinylabscom/mvm-images",
            "release_tag": "image-set/v0.2.4",
            "manifest_sha256": "a" * 64,
        }
        self.source.write_text(
            'version = "1.1.0"\n[image_build]\nplatform = "linux/x86_64"\n'
            '[image_build.base_set]\nrepository = "tinylabscom/mvm-images"\n'
            'release_tag = "image-set/v0.2.4"\nmanifest_sha256 = "' + "a" * 64 + '"\n'
        )
        self.sidecar.write_text(json.dumps({
            "entrypointArgv": ["/bin/sleep", "infinity"],
        }))
        self.marker = b"#!/bin/sh\nexec /bin/sleep infinity\n"
        self.pin = checker.BaseEntrypointPin(
            base_set=self.base,
            rootfs_sha256=hashlib.sha256(self.rootfs.read_bytes()).hexdigest(),
            marker_sha256=hashlib.sha256(self.marker).hexdigest(),
            argv=("/bin/sleep", "infinity"),
        )

    def run_check(self, marker=None):
        result = subprocess.CompletedProcess(
            args=["debugfs"], returncode=0,
            stdout=self.marker if marker is None else marker, stderr=b"",
        )
        with mock.patch.object(checker.subprocess, "run", return_value=result) as command:
            checker.verify(self.rootfs, self.source, self.sidecar, self.pin)
        command.assert_called_once()

    def test_matching_pinned_base_marker_and_sidecar_pass(self):
        self.run_check()

    def test_python_pid_one_claim_refuses(self):
        self.sidecar.write_text(json.dumps({"entrypointArgv": ["/bin/python3"]}))
        with self.assertRaisesRegex(checker.EntrypointError, "entrypoint argv"):
            self.run_check()

    def test_changed_base_bytes_refuse_before_debugfs(self):
        self.rootfs.write_bytes(b"different rootfs")
        with mock.patch.object(checker.subprocess, "run") as command:
            with self.assertRaisesRegex(checker.EntrypointError, "rootfs digest"):
                checker.verify(self.rootfs, self.source, self.sidecar, self.pin)
        command.assert_not_called()

    def test_changed_base_marker_refuses(self):
        with self.assertRaisesRegex(checker.EntrypointError, "entrypoint bytes"):
            self.run_check(b"#!/bin/sh\nexec /bin/python3\n")

    def test_duplicate_sidecar_key_and_failed_inspection_refuse(self):
        self.sidecar.write_text(
            '{"entrypointArgv":["/bin/sleep","infinity"],'
            '"entrypointArgv":["/bin/sleep","infinity"]}'
        )
        with self.assertRaisesRegex(checker.EntrypointError, "sidecar is invalid"):
            self.run_check()
        self.sidecar.write_text(json.dumps({
            "entrypointArgv": ["/bin/sleep", "infinity"],
        }))
        result = subprocess.CompletedProcess(
            args=["debugfs"], returncode=1, stdout=b"", stderr=b"missing",
        )
        with mock.patch.object(checker.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(checker.EntrypointError, "entrypoint bytes"):
                checker.verify(self.rootfs, self.source, self.sidecar, self.pin)

    def test_moved_base_pin_and_linked_rootfs_refuse(self):
        self.source.write_text(self.source.read_text().replace("a" * 64, "b" * 64))
        with self.assertRaisesRegex(checker.EntrypointError, "base set"):
            self.run_check()
        self.source.write_text(self.source.read_text().replace("b" * 64, "a" * 64))
        self.rootfs.unlink()
        self.rootfs.symlink_to(self.source)
        with self.assertRaisesRegex(checker.EntrypointError, "regular rootfs"):
            self.run_check()


if __name__ == "__main__":
    unittest.main()
