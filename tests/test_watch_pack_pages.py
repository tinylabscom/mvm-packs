import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
snapshot = runpy.run_path(str(ROOT / "scripts/watch-pack-pages.py"))["snapshot"]


class WatchPackPagesTests(unittest.TestCase):
    def test_snapshot_tracks_input_changes_but_not_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "packs").mkdir()
            (root / "index.json").write_text("{}")
            initial = snapshot(root)

            output = root / "docs/registry/README.md"
            output.parent.mkdir(parents=True)
            output.write_text("generated")
            self.assertEqual(snapshot(root), initial)

            (root / "revocations.toml").write_text("revoked")
            self.assertNotEqual(snapshot(root), initial)
            initial = snapshot(root)

            manifest = root / "packs/agent/claude/1.0.1/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("{}")
            self.assertNotEqual(snapshot(root), initial)
            initial = snapshot(root)

            manifest.unlink()
            self.assertNotEqual(snapshot(root), initial)
