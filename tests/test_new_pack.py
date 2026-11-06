import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder
ROOT = Path(__file__).resolve().parents[1]
create = runpy.run_path(str(ROOT / "scripts/new-pack.py"))["create"]


class NewPackTests(unittest.TestCase):
    def test_creates_application_draft_that_must_be_filled_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = create(root, "acme", "example")
            self.assertIn('version = "0.1.0"', (source / "pack.toml").read_text())
            self.assertIn("[application.bundle]", (source / "pack.toml").read_text())
            self.assertEqual([p.name for p in source.iterdir()], ["pack.toml"])
            with patch.object(builder, "PACKS", root / "packs"), self.assertRaises(SystemExit):
                builder.build_one(source, check_only=True)
            self.assertFalse((root / "packs").exists())
            with self.assertRaises(FileExistsError):
                create(root, "acme", "example")

    def test_policy_only_source_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "pack-sources/acme/policy"
            (source / "pack").mkdir(parents=True)
            (source / "pack.toml").write_text('version = "1.0.0"\ndescription = "Policy"\n')
            (source / "pack/group.toml").write_text("[network]\nallow = []\n")
            with patch.object(builder, "PACKS", Path(directory) / "packs"), \
                    self.assertRaisesRegex(SystemExit, "embed its application binary"):
                builder.build_one(source, check_only=True)

    def test_source_check_refuses_changes_to_published_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = create(root, "acme", "example")
            (source / "pack.toml").write_text(
                (source / "pack.toml").read_text().replace("REPLACE.mvmpkg", "x.mvmpkg"))
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
