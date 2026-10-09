"""A pack sidecar is derived from a pinned base template and measured image."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build-python-sidecar.py"
SPEC = importlib.util.spec_from_file_location("build_python_sidecar", SCRIPT)
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)


class PythonSidecarProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base_meta = self.root / "default-microvm-meta-x86_64.json"
        self.base_rootfs = self.root / "default-microvm-rootfs-x86_64.ext4"
        self.composed = self.root / "rootfs.ext4"
        self.source = self.root / "pack.toml"
        self.output = self.root / "mvm-meta.json"
        self.base_rootfs.write_bytes(b"base")
        self.composed.write_bytes(b"composed")
        self.source.write_text('version = "1.1.0"\n')
        self.metadata = {
            "accessible": False, "agentBinary": "real", "builtAt": "",
            "entrypointKind": "command", "expectedBootMs": 300,
            "generatorRev": "4e65b221744885e536ec91a3f2948cdc508dcb49",
            "hypervisor": "firecracker", "imageTag": "", "initSystem": "busybox",
            "name": "mvm-default-microvm", "overlayAware": True,
            "protocolVersion": 2, "rootlessEntrypoint": True,
            "runtimeLean": True, "sealed": True, "source": "built-local",
        }
        self.base_meta.write_text(json.dumps(self.metadata))
        self.template_digest = hashlib.sha256(self.base_meta.read_bytes()).hexdigest()

    def build(self):
        with patch.object(producer, "TEMPLATE_SHA256", self.template_digest), \
                patch.object(producer.base, "verify") as base_check, \
                patch.object(producer.runtime, "verify") as runtime_check:
            producer.build(self.base_meta, self.base_rootfs, self.composed,
                           self.source, self.output)
        return base_check, runtime_check

    def test_pinned_template_and_image_checks_produce_sealed_sidecar(self):
        base_check, runtime_check = self.build()
        produced = json.loads(self.output.read_text())
        self.assertEqual(produced["entrypointArgv"], ["/bin/sleep", "infinity"])
        self.assertEqual(produced["libc"], "glibc")
        self.assertEqual({k: v for k, v in produced.items()
                          if k not in ("entrypointArgv", "libc")}, self.metadata)
        self.assertEqual(base_check.call_count, 1)
        self.assertEqual(base_check.call_args.args[:2], (self.base_rootfs, self.source))
        self.assertEqual(runtime_check.call_count, 1)
        self.assertEqual(runtime_check.call_args.args[0], self.composed)
        self.assertEqual(runtime_check.call_args.args[1], base_check.call_args.args[2])
        self.assertEqual(base_check.call_args.args[2].name, "mvm-meta.json")

    def test_changed_or_duplicate_template_refuses_without_output(self):
        with self.assertRaisesRegex(producer.SidecarError, "template digest"):
            producer.build(self.base_meta, self.base_rootfs, self.composed,
                           self.source, self.output)
        self.assertFalse(self.output.exists())
        self.base_meta.write_text('{"sealed":true,"sealed":false}')
        with patch.object(producer, "TEMPLATE_SHA256",
                          hashlib.sha256(self.base_meta.read_bytes()).hexdigest()):
            with self.assertRaisesRegex(producer.SidecarError, "template"):
                producer.build(self.base_meta, self.base_rootfs, self.composed,
                               self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_failed_final_image_check_refuses_without_output(self):
        with patch.object(producer, "TEMPLATE_SHA256", self.template_digest), \
                patch.object(producer.base, "verify"), \
                patch.object(producer.runtime, "verify",
                             side_effect=producer.runtime.RuntimeCheckError("changed init")):
            with self.assertRaisesRegex(producer.SidecarError, "composed runtime"):
                producer.build(self.base_meta, self.base_rootfs, self.composed,
                               self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_and_symlink_template_refuse(self):
        self.output.write_bytes(b"existing")
        with self.assertRaisesRegex(producer.SidecarError, "new output"):
            self.build()
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.output.unlink()
        linked = self.root / "linked.json"
        linked.symlink_to(self.base_meta)
        with self.assertRaisesRegex(producer.SidecarError, "regular template"):
            with patch.object(producer, "TEMPLATE_SHA256", self.template_digest):
                producer.build(linked, self.base_rootfs, self.composed,
                               self.source, self.output)


if __name__ == "__main__":
    unittest.main()
