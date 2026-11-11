import hashlib
import importlib.util
import json
import pathlib
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import application_manifest as am  # noqa: E402

spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build-packs.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

FIXTURES = {
    "x86_64": (
        ROOT / "tests/layer-fixtures/runtime-python",
        "1.1.0", "9f5dfaf983a54a62212184f08f5dfc36d1474052d71a799cdfd3f1a53dc970d4",
        63836160,
    ),
    "aarch64": (
        ROOT / "tests/layer-fixtures/runtime-python-aarch64",
        "1.1.1", "2c65e1c400098a3a8141a58f2f2f66a3df667d5f947d86d982f3d115b023b0f2",
        64798720,
    ),
}


class RuntimePythonLayerFixture(unittest.TestCase):
    def test_fixture_parses_and_renders_a_deterministic_manifest(self):
        for arch, (fixture, version, digest, size) in FIXTURES.items():
            with self.subTest(arch=arch):
                meta = builder.parse_pack_toml(fixture / "pack.toml")
                policy = (fixture / "pack/group.toml").read_bytes()
                files = [{"path": "pack/group.toml", "sha256": hashlib.sha256(policy).hexdigest(),
                          "size": len(policy)}]
                render = lambda: am.runtime_layer_manifest_bytes(
                    "runtime/python@" + meta["version"], meta["description"], meta["runtime_layer"], files)
                first = render()
                self.assertEqual(first, render())
                manifest = json.loads(first)
                self.assertEqual((manifest["schema_version"], manifest["kind"], manifest["reference"]),
                                 (3, "runtime_layer", f"runtime/python@{version}"))
                self.assertEqual(manifest["runtime_layer"]["guest_arch"], arch)
                self.assertEqual(manifest["runtime_layer"]["archive"]["archive_sha256"], digest)
                self.assertEqual(manifest["runtime_layer"]["archive"]["archive_size"], size)
                self.assertEqual(manifest["files"], files)

    def test_fixture_policy_is_required_and_offline(self):
        for arch, (fixture, _, _, _) in FIXTURES.items():
            with self.subTest(arch=arch):
                group = tomllib.loads((fixture / "pack/group.toml").read_text())
                self.assertEqual(set(group), {"description", "required", "network"})
                self.assertIs(group["required"], True)
                self.assertEqual(group["network"], {"block": True})


if __name__ == "__main__":
    unittest.main()
