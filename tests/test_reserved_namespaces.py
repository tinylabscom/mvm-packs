import runpy
import unittest
from pathlib import Path

violations = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check-reserved-namespaces.py"))["violations"]


class ReservedNamespaceTests(unittest.TestCase):
    def test_outsider_cannot_touch_first_party_namespaces(self):
        for path in ("pack-sources/agent/x/pack.toml", "pack-sources/runtime/x/pack/group.toml",
                     "pack-sources/mvm/x/pack.toml", "packs/agent/claude/1.0.1/manifest.json", "index.json"):
            with self.subTest(path=path):
                self.assertEqual(violations([path], "CONTRIBUTOR"), [path])
                self.assertEqual(violations([path], "FIRST_TIME_CONTRIBUTOR"), [path])

    def test_maintainers_and_other_namespaces_pass(self):
        self.assertEqual(violations(["pack-sources/agent/x/pack.toml"], "MEMBER"), [])
        self.assertEqual(violations(["pack-sources/agent/x/pack.toml"], "OWNER"), [])
        self.assertEqual(violations(["pack-sources/acme/x/pack.toml", "agentx/y", "README.md"], "NONE"), [])
