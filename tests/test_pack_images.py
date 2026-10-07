"""Publisher contract tests for signed image-bearing pack manifests."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-packs.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("build_packs", SCRIPT)
build_packs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_packs)


class PackImageTests(unittest.TestCase):
    def test_source_image_cannot_be_published_without_built_artifact_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pack-sources" / "runtime" / "python"
            image_dir = source / "pack" / "image"
            image_dir.mkdir(parents=True)
            (source / "pack.toml").write_text(
                'version = "1.0.0"\ndescription = "Python"\n'
                '[image]\nmanifest = "pack/image/mvm.toml"\n'
            )
            (image_dir / "mvm.toml").write_text('flake = "."\n')
            (image_dir / "flake.nix").write_text("{}\n")
            (image_dir / "flake.lock").write_text("{}\n")
            with patch.object(build_packs, "PACKS", root / "packs"), \
                    patch.object(build_packs, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "built image digest"):
                    build_packs.build_one(source)
            sign.assert_not_called()
            self.assertFalse((root / "packs").exists())

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
