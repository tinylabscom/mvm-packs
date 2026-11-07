import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import application_manifest as am  # noqa: E402

spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build-packs.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

PIN = {"reference": "runtime/python@1.2.3", "manifest_sha256": "c" * 64}
REF = "runtime/node@2.0.0"


def layer(**changes):
    return {"schema_version": 1, "guest_arch": "aarch64", "dependencies": [PIN], **changes}


def files(*paths):
    return [{"path": p, "sha256": "a" * 64, "size": 10} for p in paths]


class RuntimeLayerTests(unittest.TestCase):
    def test_valid_manifest_bytes(self):
        raw = am.runtime_layer_manifest_bytes(
            REF, "d", layer(), files("pack/group.toml", "layer.tar"))
        self.assertIn(b'"kind": "runtime_layer"', raw)
        self.assertIn(b'"schema_version": 3', raw)
        am.validate_runtime_layer(layer(dependencies=[]), REF)

    def test_bad_layers_are_refused(self):
        bad = [layer(extra=1), layer(schema_version=2), layer(guest_arch="riscv"),
               layer(dependencies=[PIN, PIN]), layer(dependencies=[dict(PIN, extra=1)]),
               layer(dependencies=[{"reference": "agent/claude@1.0.0", "manifest_sha256": "c" * 64}]),
               layer(dependencies=[{"reference": REF, "manifest_sha256": "c" * 64}]),
               layer(dependencies=[dict(PIN, manifest_sha256="C" * 64)]),
               layer(dependencies=[dict(PIN, reference="runtime/python@1.2")]),
               layer(dependencies=[PIN] * 17), layer(dependencies="x")]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                am.validate_runtime_layer(value, REF)

    def test_file_inventory_is_closed(self):
        am.validate_layer_files(files("layer.tar", "pack/profile.toml"))
        big = files("layer.tar", "pack/group.toml")
        big[0]["size"] = am.MAX_LAYER_TAR + 1
        for value in (files("layer.tar"), files("pack/group.toml"),
                      files("layer.tar", "pack/group.toml", "pack/group.toml"),
                      files("layer.tar", "pack/group.toml", "extra"), big,
                      [dict(files("layer.tar")[0], size=0)] + files("pack/group.toml")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                am.validate_layer_files(value)

    def test_application_descriptor_is_unchanged(self):
        with self.assertRaises(ValueError):
            am.validate_application({"schema_version": 1, "guest_arch": "aarch64", "layers": [PIN],
                                     "bundle": {"source": "https://e.com/x", "archive_sha256": "a" * 64,
                                                "archive_size": 1, "key_id": "b" * 32}})

    def test_runtime_layers_are_not_publishable_yet(self):
        body = ('[runtime_layer]\nschema_version = 1\nguest_arch = "aarch64"\ndependencies = []\n')
        with tempfile.TemporaryDirectory() as d:
            source = pathlib.Path(d) / "pack-sources/runtime/x"
            source.mkdir(parents=True)
            (source / "pack.toml").write_text('version = "1.0.0"\ndescription = "x"\n' + body)
            with self.assertRaisesRegex(SystemExit, "not publishable"):
                builder.build_one(source, check_only=True)


if __name__ == "__main__":
    unittest.main()
