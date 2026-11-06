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

BUNDLE = {"source": "https://example.com/x.mvmpkg", "archive_sha256": "a" * 64,
          "archive_size": 10, "key_id": "b" * 32}
PIN = {"reference": "runtime/python@1.2.3", "manifest_sha256": "c" * 64}


def layer():
    return {"schema_version": 1, "guest_arch": "aarch64", "bundle": dict(BUNDLE)}


class LayerDescriptorTests(unittest.TestCase):
    def test_valid_layer_and_application_with_layers(self):
        am.validate_layer(layer())
        app = layer()
        app["layers"] = [PIN, {"reference": "runtime/node@2.0.0", "manifest_sha256": "d" * 64}]
        am.validate_application(app)
        self.assertIn(b'"kind": "layer"', am.layer_manifest_bytes("acme/py@1.0.0", "d", layer()))

    def test_bad_pins_are_refused(self):
        bad = [[], [PIN, PIN], [{"reference": "runtime/python", "manifest_sha256": "c" * 64}],
               [{"reference": "runtime/python@1.2", "manifest_sha256": "c" * 64}],
               [{"reference": "runtime/python@1.2.3", "manifest_sha256": "C" * 64}],
               [{**PIN, "extra": 1}], [PIN] * 17, "x"]
        for pins in bad:
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                am.validate_layer_pins(pins)

    def test_a_layer_cannot_compose_layers(self):
        value = layer()
        value["layers"] = [PIN]
        with self.assertRaises(ValueError):
            am.validate_layer(value)

    def test_layers_are_not_publishable_yet(self):
        for body in (
            '[layer]\nschema_version = 1\nguest_arch = "aarch64"\n[layer.bundle]\n'
            'source = "https://example.com/x.mvmpkg"\narchive_sha256 = "%s"\narchive_size = 10\n'
            'key_id = "%s"\n' % ("a" * 64, "b" * 32),
            '[application]\nschema_version = 1\nguest_arch = "aarch64"\n'
            'layers = [{reference = "runtime/python@1.2.3", manifest_sha256 = "%s"}]\n'
            '[application.bundle]\nsource = "https://example.com/x.mvmpkg"\narchive_sha256 = "%s"\n'
            'archive_size = 10\nkey_id = "%s"\n' % ("c" * 64, "a" * 64, "b" * 32),
        ):
            with tempfile.TemporaryDirectory() as d:
                source = pathlib.Path(d) / "pack-sources/acme/x"
                source.mkdir(parents=True)
                (source / "pack.toml").write_text('version = "1.0.0"\ndescription = "x"\n' + body)
                with self.assertRaisesRegex(SystemExit, "not publishable"):
                    builder.build_one(source, check_only=True)


if __name__ == "__main__":
    unittest.main()
