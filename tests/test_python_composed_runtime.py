"""The signing lane measures Python and glibc from the final ext4 bytes."""

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_stage_python_closure import elf_with_interpreter


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check-python-composed-runtime.py"
SPEC = importlib.util.spec_from_file_location("check_python_composed_runtime", SCRIPT)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def e2fs_tool(name):
    return shutil.which(name) or str(Path("/opt/homebrew/opt/e2fsprogs/sbin") / name)


class ComposedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tree = self.root / "tree"
        self.tree.mkdir()
        self.image = self.root / "rootfs.ext4"
        self.sidecar = self.root / "mvm-meta.json"
        self.python_name = f"{'a' * 32}-python3-3.12"
        self.glibc_name = f"{'b' * 32}-glibc-2.40"
        self.loader_path = f"/nix/store/{self.glibc_name}/lib/ld-linux-x86-64.so.2"
        self.python_path = self.tree / "nix/store" / self.python_name / "bin/python3.12"
        self.loader = self.tree / "nix/store" / self.glibc_name / "lib/ld-linux-x86-64.so.2"
        self.python_path.parent.mkdir(parents=True)
        self.loader.parent.mkdir(parents=True)
        self.python_path.write_bytes(elf_with_interpreter(self.loader_path))
        self.python_path.chmod(0o755)
        (self.python_path.parent / "python3").symlink_to("python3.12")
        self.loader.write_bytes(elf_with_interpreter(self.loader_path))
        self.loader.chmod(0o755)
        (self.tree / "bin").mkdir()
        (self.tree / "bin/python3").symlink_to(
            f"/nix/store/{self.python_name}/bin/python3"
        )
        (self.tree / "lib64").mkdir()
        (self.tree / "lib64/ld-linux-x86-64.so.2").symlink_to(self.loader_path)
        self.init = b"#!/bin/sh\nexec /etc/mvm/entrypoint\n"
        self.marker = b"#!/bin/sh\nexec /bin/sleep infinity\n"
        (self.tree / "init").write_bytes(self.init)
        (self.tree / "init").chmod(0o755)
        (self.tree / "etc/mvm").mkdir(parents=True)
        (self.tree / "etc/mvm/entrypoint").write_bytes(self.marker)
        (self.tree / "etc/mvm/entrypoint").chmod(0o755)
        self.boot_pin = runtime.FinalBootPin(
            init_sha256=hashlib.sha256(self.init).hexdigest(),
            marker_sha256=hashlib.sha256(self.marker).hexdigest(),
            argv=("/bin/sleep", "infinity"),
        )
        self.metadata = {
            "name": "mvm-default-microvm", "accessible": False, "sealed": True,
            "entrypointKind": "command", "entrypointArgv": ["/bin/sleep", "infinity"],
            "initSystem": "busybox", "expectedBootMs": 300, "agentBinary": "real",
            "rootlessEntrypoint": True, "hypervisor": "firecracker",
            "overlayAware": True, "runtimeLean": True, "protocolVersion": 2,
            "libc": "glibc",
        }
        self.sidecar.write_text(json.dumps(self.metadata), encoding="utf-8")

    def build_ext4(self):
        if not Path(e2fs_tool("mke2fs")).is_file() or not Path(e2fs_tool("debugfs")).is_file():
            self.skipTest("e2fsprogs is unavailable")
        with self.image.open("wb") as destination:
            destination.truncate(16 << 20)
        result = subprocess.run(
            [e2fs_tool("mke2fs"), "-q", "-F", "-t", "ext4", "-d", str(self.tree),
             str(self.image)], capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def verify(self):
        directory = str(Path(e2fs_tool("debugfs")).parent)
        with patch.dict(os.environ, {"PATH": f"{directory}:{os.environ['PATH']}"}):
            runtime.verify(self.image, self.sidecar, self.boot_pin)

    def test_accepts_matching_composed_python_and_glibc(self):
        self.build_ext4()
        self.verify()

    def test_refuses_python_elf_with_a_different_loader(self):
        other = f"/nix/store/{'c' * 32}-glibc-2.40/lib/ld-linux-x86-64.so.2"
        self.python_path.write_bytes(elf_with_interpreter(other))
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "different glibc loader"):
            self.verify()

    def test_refuses_missing_loader_link(self):
        (self.tree / "lib64/ld-linux-x86-64.so.2").unlink()
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "omits a readable"):
            self.verify()

    def test_refuses_non_elf_loader(self):
        self.loader.write_bytes(b"not an ELF loader")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "not x86-64 ELF"):
            self.verify()

    def test_refuses_python_link_outside_its_store_output(self):
        (self.tree / "bin/python3").unlink()
        (self.tree / "bin/python3").symlink_to("/bin/sh")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "escapes its pinned store output"):
            self.verify()

    def test_refuses_non_executable_python(self):
        self.python_path.chmod(0o644)
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "not executable"):
            self.verify()

    def test_refuses_sidecar_libc_mismatch(self):
        self.metadata["libc"] = "musl"
        self.sidecar.write_text(json.dumps(self.metadata), encoding="utf-8")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "declare the measured glibc"):
            self.verify()

    def test_refuses_changed_final_entrypoint(self):
        (self.tree / "etc/mvm/entrypoint").write_bytes(b"#!/bin/sh\nexec /bin/python3\n")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "entrypoint differs"):
            self.verify()

    def test_refuses_alternate_boot_file(self):
        (self.tree / "etc/mvm/boot").write_bytes(b"#!/bin/sh\nexec /bin/python3\n")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "alternate boot"):
            self.verify()

    def test_refuses_changed_final_init(self):
        (self.tree / "init").write_bytes(b"#!/bin/sh\nexec /bin/python3\n")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "init differs"):
            self.verify()

    def test_refuses_nonexecutable_final_init(self):
        (self.tree / "init").chmod(0o644)
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "init is not executable"):
            self.verify()

    def test_refuses_sidecar_boot_argv_mismatch(self):
        self.metadata["entrypointArgv"] = ["/bin/python3"]
        self.sidecar.write_text(json.dumps(self.metadata), encoding="utf-8")
        self.build_ext4()
        with self.assertRaisesRegex(runtime.RuntimeCheckError, "entrypoint argv"):
            self.verify()

    def test_refuses_ambiguous_alternate_boot_absence(self):
        result = subprocess.CompletedProcess(
            args=["debugfs"], returncode=0, stdout="", stderr="unexpected diagnostic",
        )
        with patch.object(runtime.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(runtime.RuntimeCheckError, "absence could not be established"):
                runtime.refuse_alternate_boot(self.image)


if __name__ == "__main__":
    unittest.main()
