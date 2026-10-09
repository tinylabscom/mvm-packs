"""The Python application tree contains a complete, pinned Nix closure."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stage-python-closure.py"
SPEC = importlib.util.spec_from_file_location("stage_python_closure", SCRIPT)
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


class StagePythonClosureTests(unittest.TestCase):
    def test_flake_source_and_lock_name_the_same_immutable_nixpkgs_revision(self):
        flake = stage.IMAGE_FLAKE
        lock = json.loads((flake / "flake.lock").read_text())
        nixpkgs = lock["nodes"]["nixpkgs"]
        revision = nixpkgs["locked"]["rev"]
        self.assertEqual(nixpkgs["original"]["rev"], revision)
        self.assertIn(f"github:NixOS/nixpkgs/{revision}", (flake / "flake.nix").read_text())
        self.assertEqual(
            nixpkgs["locked"]["narHash"],
            "sha256-Ti+ZBvW6yrWWAg2szExVTwCd4qOJ3KlVr1tFHfyfi8Q=",
        )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = self.root / "nix" / "store"
        self.store.mkdir(parents=True)
        self.python = self.store / f"{'a' * 32}-python3-3.12"
        (self.python / "bin").mkdir(parents=True)
        executable = self.python / "bin" / "python3.12"
        executable.write_bytes(b"python executable")
        executable.chmod(0o755)
        (self.python / "bin" / "python3").symlink_to("python3.12")
        self.libc = self.store / f"{'b' * 32}-glibc"
        (self.libc / "lib").mkdir(parents=True)
        (self.libc / "lib" / "ld.so").write_bytes(b"loader")
        self.data = self.store / f"{'e' * 32}-runtime-data"
        self.data.write_bytes(b"runtime data")
        self.output = self.root / "staged"

    def test_stages_complete_closure_and_guest_interpreter_link(self):
        stage.stage_closure(self.python, [self.data, self.libc, self.python], self.output, self.store)
        self.assertEqual(
            (self.output / "nix" / "store" / self.libc.name / "lib" / "ld.so").read_bytes(),
            b"loader",
        )
        self.assertEqual(
            os.readlink(self.output / "nix" / "store" / self.python.name / "bin" / "python3"),
            "python3.12",
        )
        self.assertEqual(
            os.readlink(self.output / "bin" / "python3"),
            f"/nix/store/{self.python.name}/bin/python3",
        )
        self.assertEqual(
            (self.output / "nix" / "store" / self.data.name).read_bytes(),
            b"runtime data",
        )
        with self.assertRaisesRegex(stage.StageError, "already exists"):
            stage.stage_closure(self.python, [self.data, self.libc, self.python], self.output, self.store)

    def test_refuses_out_of_store_or_missing_closure_members(self):
        outside = self.root / "outside"
        outside.mkdir()
        missing = self.store / f"{'d' * 32}-missing"
        for paths in ([self.python, outside], [self.python, missing],
                      [self.libc], [self.python, self.python]):
            with self.subTest(paths=paths), self.assertRaises(stage.StageError):
                stage.stage_closure(self.python, paths, self.output, self.store)
            self.assertFalse(self.output.exists())

    def test_refuses_a_linked_store_member_and_missing_interpreter(self):
        linked = self.store / f"{'c' * 32}-linked"
        linked.symlink_to(self.python)
        with self.assertRaises(stage.StageError):
            stage.stage_closure(self.python, [self.python, linked], self.output, self.store)
        (self.python / "bin" / "python3").unlink()
        with self.assertRaisesRegex(stage.StageError, "Python executable"):
            stage.stage_closure(self.python, [self.python], self.output, self.store)
        self.assertFalse(self.output.exists())

    def test_nix_build_uses_the_checked_in_lock_and_queries_requisites(self):
        with patch.object(stage.sys, "platform", "linux"), \
                patch.object(stage, "run_nix", side_effect=[
                    [str(self.python)], [str(self.libc), str(self.python)]
                ]) as nix, patch.object(stage, "stage_closure") as stage_tree:
            stage.build_and_stage(self.output)
        self.assertEqual(nix.call_args_list, [
            call([
                "nix", "--extra-experimental-features", "nix-command flakes", "build",
                "--no-link", "--print-out-paths", "--no-update-lock-file",
                f"path:{stage.IMAGE_FLAKE}#default",
            ]),
            call(["nix-store", "--query", "--requisites", str(self.python)]),
        ])
        stage_tree.assert_called_once_with(
            str(self.python), [str(self.libc), str(self.python)], self.output,
        )

    def test_nix_failure_and_multiple_build_outputs_refuse_staging(self):
        failed = subprocess.CompletedProcess(["nix"], 1, stdout="", stderr="secret")
        with patch.object(stage.subprocess, "run", return_value=failed), \
                self.assertRaisesRegex(stage.StageError, "exit status 1"):
            stage.run_nix(["nix", "build"])
        with patch.object(stage.sys, "platform", "linux"), \
                patch.object(stage, "run_nix", return_value=[str(self.python), str(self.libc)]), \
                patch.object(stage, "stage_closure") as stage_tree, \
                self.assertRaisesRegex(stage.StageError, "no unique store output"):
            stage.build_and_stage(self.output)
        stage_tree.assert_not_called()

    def test_nix_uses_a_writable_private_cache_without_exposing_stderr(self):
        def check_environment(arguments, **options):
            cache = Path(options["env"]["XDG_CACHE_HOME"])
            self.assertTrue(cache.is_dir())
            self.assertEqual(cache.parent, Path("/tmp"))
            return subprocess.CompletedProcess(arguments, 1, stdout="", stderr="private data")

        with patch.object(stage.subprocess, "run", side_effect=check_environment), \
                self.assertRaises(stage.StageError) as raised:
            stage.run_nix(["nix", "build"])
        self.assertNotIn("private data", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
