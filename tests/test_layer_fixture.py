import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import application_manifest as am  # noqa: E402

spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build-packs.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

FIXTURE = ROOT / "tests/layer-fixtures/runtime-python"


class RuntimePythonLayerFixture(unittest.TestCase):
    def test_fixture_parses_and_renders_a_deterministic_manifest(self):
        meta = builder.parse_pack_toml(FIXTURE / "pack.toml")
        policy = (FIXTURE / "pack/group.toml").read_bytes()
        files = [{"path": "pack/group.toml", "sha256": hashlib.sha256(policy).hexdigest(),
                  "size": len(policy)}]
        render = lambda: am.runtime_layer_manifest_bytes(
            "runtime/python@" + meta["version"], meta["description"], meta["runtime_layer"], files)
        first = render()
        self.assertEqual(first, render())
        manifest = json.loads(first)
        self.assertEqual((manifest["schema_version"], manifest["kind"], manifest["reference"]),
                         (3, "runtime_layer", "runtime/python@1.1.0"))
        self.assertEqual(manifest["runtime_layer"]["guest_arch"], "x86_64")
        self.assertEqual(manifest["files"], files)


if __name__ == "__main__":
    unittest.main()
