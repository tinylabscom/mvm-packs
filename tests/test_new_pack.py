import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder
ROOT = Path(__file__).resolve().parents[1]
create = runpy.run_path(str(ROOT / "scripts/new-pack.py"))["create"]


class NewPackTests(unittest.TestCase):
    def test_creates_unprivileged_policy_draft_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = create(root, "acme", "example")
            self.assertIn('version = "0.1.0"', (source / "pack.toml").read_text())
            self.assertIn("allow = []", (source / "pack/group.toml").read_text())
            self.assertIn("never include values", (source / "pack/README.md").read_text())
            with patch.object(builder, "PACKS", root / "packs"):
                builder.build_one(source, check_only=True)
            self.assertFalse((root / "packs").exists())
            with self.assertRaises(FileExistsError):
                create(root, "acme", "example")

    def test_source_check_refuses_changes_to_published_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = create(root, "acme", "example")
            published = root / "packs/acme/example/0.1.0"
            published.mkdir(parents=True)
            (published / "manifest.json").write_text("different bytes")
            with patch.object(builder, "PACKS", root / "packs"), self.assertRaises(SystemExit):
                builder.build_one(source, check_only=True)

    def test_rejects_unsafe_names_before_creating_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("../bad", "CAPS", "with space", ""):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    create(root, "acme", name)
            for reserved in ("mvm", "agent", "runtime"):
                with self.subTest(reserved=reserved), self.assertRaises(ValueError):
                    create(root, reserved, "example")
            self.assertFalse((root / "pack-sources").exists())

    def test_rejects_symlinked_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pack-sources").mkdir()
            (root / "pack-sources/acme").symlink_to(root)
            with self.assertRaises(ValueError):
                create(root, "acme", "example")
            self.assertFalse((root / "pack").exists())
