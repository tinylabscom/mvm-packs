"""Producer structure validation does not authorize archive publication."""
import copy
import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
BUILD = runpy.run_path(str(SCRIPTS / "build-packs.py"))


class ApplicationPackageTests(unittest.TestCase):
    def declaration(self):
        return {"schema_version": 1, "archives": {"x86_64": {
            "url": "https://github.com/example/project/releases/download/v1.2.3/app.mvmpkg",
            "sha256": "a" * 64, "size_bytes": 1024, "key_id": "b" * 32,
        }}}

    def test_valid_declaration(self):
        value = self.declaration()
        value["archives"]["aarch64"] = copy.deepcopy(value["archives"]["x86_64"])
        BUILD["validate_application_declaration"](value, "example/app@1.2.3")

    def test_invalid_declarations(self):
        mutations = [
            lambda d: d.update(extra=True),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(archives={}),
            lambda d: d["archives"].update(amd64=d["archives"]["x86_64"]),
        ]
        for field, values in {
            "sha256": ["A" * 64, "0", None],
            "size_bytes": [True, 0, -1, 4 * 1024**3 + 1, 1.5],
            "key_id": ["A" * 32, "b" * 64, ""],
            "url": [
                "http://github.com/o/r/releases/download/v1/a.mvmpkg",
                "https://github.com/o/r/releases/download/latest/a.mvmpkg",
                "https://github.com/o/r/releases/download/v1/a.mvmpkg?q=x",
                "https://user@github.com/o/r/releases/download/v1/a.mvmpkg",
                "https://example.com/o/r/releases/download/v1/a.mvmpkg",
                "https://github.com/o/r/releases/download/v1/a.mvmpkg#fragment",
            ],
            "unknown": [1],
        }.items():
            for value in values:
                mutations.append(lambda d, f=field, v=value: d["archives"]["x86_64"].update({f: v}))
        for mutation in mutations:
            data = self.declaration()
            mutation(data)
            with self.subTest(data=data), self.assertRaises(SystemExit):
                BUILD["validate_application_declaration"](data, "example/app@1.2.3")

    def test_profile_required_and_declaration_signed(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            payload = Path(temporary)
            (payload / "application.json").write_text(json.dumps(self.declaration()))
            with self.assertRaisesRegex(SystemExit, "profile"):
                BUILD["validate_application_payload"](payload, "example/app@1.2.3")
            (payload / "profile.toml").write_text("schema_version = 1\n")
            with self.assertRaisesRegex(SystemExit, "must be signed"):
                BUILD["validate_application_payload"](payload, "example/app@1.2.3", set())
            _, files = BUILD["manifest_bytes"]("example/app@1.2.3", "Example", payload)
            self.assertEqual({f["path"] for f in files}, {"pack/application.json", "pack/profile.toml"})

    def test_build_refuses_before_signing(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            source = Path(temporary) / "example" / "app"
            payload = source / "pack"
            payload.mkdir(parents=True)
            (source / "pack.toml").write_text('version = "1.2.3"\ndescription = "Example"\n')
            (payload / "application.json").write_text(json.dumps(self.declaration()))
            (payload / "profile.toml").write_text("schema_version = 1\n")
            with patch.dict(BUILD["build_one"].__globals__, {"sign": lambda *args: self.fail("sign called")}):
                with self.assertRaisesRegex(SystemExit, "protected archive signing/evidence"):
                    BUILD["build_one"](source)

    def test_policy_only_unchanged(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            payload = Path(temporary)
            (payload / "profile.toml").write_text("schema_version = 1\n")
            self.assertFalse(BUILD["validate_application_payload"](payload, "example/policy@1.0.0"))
            manifest, _ = BUILD["manifest_bytes"]("example/policy@1.0.0", "Policy", payload)
            self.assertEqual(set(json.loads(manifest)), {"schema_version", "reference", "description", "files"})

    def test_registry_validation_reuses_application_checks(self):
        validator = runpy.run_path(str(SCRIPTS / "validate-packs.py"))
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            packs = root / "packs"
            output = packs / "example" / "app" / "1.2.3"
            payload = output / "files" / "pack"
            payload.mkdir(parents=True)
            (payload / "application.json").write_text(json.dumps(self.declaration()))
            (payload / "profile.toml").write_text("schema_version = 1\n")
            manifest, _ = BUILD["manifest_bytes"]("example/app@1.2.3", "Example", payload)
            path = output / "manifest.json"
            path.write_bytes(manifest)
            (output / "manifest.sigstore.json").write_text("{}")
            function = validator["validate_manifest"]
            with patch.dict(function.__globals__, {"ROOT": root, "PACKS": packs}):
                function(path)
                self.assertEqual(validator["problems"], [])
                data = self.declaration()
                data["archives"]["x86_64"]["size_bytes"] = True
                (payload / "application.json").write_text(json.dumps(data))
                function(path)
                self.assertTrue(any("size_bytes" in problem for problem in validator["problems"]))
