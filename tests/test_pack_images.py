"""Publisher contract tests for signed image-bearing pack manifests."""

import importlib.util
import json
import tempfile
import tomllib
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-packs.py"
SPEC = importlib.util.spec_from_file_location("build_packs", SCRIPT)
build_packs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_packs)


class PackImageTests(unittest.TestCase):
    def test_python_runtime_source_is_pinned_and_publishable(self):
        source = Path(__file__).resolve().parents[1] / "pack-sources/runtime/python"
        meta = build_packs.parse_pack_toml(source / "pack.toml")
        self.assertEqual(meta["version"], "1.1.0")
        encoded, files = build_packs.manifest_bytes(
            "runtime/python@1.1.0",
            meta["description"],
            source / "pack",
            meta["image"],
        )
        manifest = json.loads(encoded)
        self.assertEqual(manifest["image"], {"manifest": "pack/image/mvm.toml"})
        self.assertEqual(len(files), 4)
        self.assertIn("pack/group.toml", {item["path"] for item in files})
        lock = json.loads((source / "pack/image/flake.lock").read_text())
        self.assertEqual(lock["nodes"]["mvm"]["locked"]["rev"],
                         "4e65b221744885e536ec91a3f2948cdc508dcb49")

    def test_python_runtime_exposes_its_own_composable_policy(self):
        source = Path(__file__).resolve().parents[1] / "pack-sources/runtime/python"
        group = tomllib.loads((source / "pack/group.toml").read_text())
        self.assertIn("files.pythonhosted.org:443", group["network"]["allow"])
        self.assertNotIn("shares", group)
        self.assertNotIn("env", group)

    def test_image_descriptor_names_only_signed_neighbors(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary)
            image_dir = payload / "image"
            image_dir.mkdir()
            (image_dir / "mvm.toml").write_text('flake = "."\n')
            (image_dir / "flake.nix").write_text("{}\n")
            (image_dir / "flake.lock").write_text('{}\n')

            encoded, files = build_packs.manifest_bytes(
                "runtime/python@1.0.0",
                "Python image",
                payload,
                {"manifest": "pack/image/mvm.toml"},
            )
            manifest = json.loads(encoded)
            self.assertEqual(manifest["image"], {"manifest": "pack/image/mvm.toml"})
            self.assertEqual(len(files), 3)

            (image_dir / "mvm.toml").write_text('[network]\nallow_hosts = ["example.com"]\n')
            with self.assertRaisesRegex(SystemExit, "host authority"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )
            (image_dir / "mvm.toml").write_text('flake = "github:elsewhere/image"\n')
            with self.assertRaisesRegex(SystemExit, "local signed flake"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )

            (image_dir / "flake.lock").unlink()
            with self.assertRaisesRegex(SystemExit, "not signed"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )

    def test_image_descriptor_refuses_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            for path in ("../mvm.toml", "pack/../mvm.toml", "pack/image/other.toml"):
                with self.subTest(path=path), self.assertRaisesRegex(SystemExit, "unsafe"):
                    build_packs.manifest_bytes(
                        "runtime/python@1.0.0",
                        "Python image",
                        Path(temporary),
                        {"manifest": path},
                    )


if __name__ == "__main__":
    unittest.main()
