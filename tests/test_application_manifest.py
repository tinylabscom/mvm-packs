"""Application manifests describe bundles without publishing software fixtures."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder, validator
from application_manifest import manifest_bytes, validate_application, validate_source


def application():
    return {
        "schema_version": 1,
        "guest_arch": "aarch64",
        "bundle": {
            "source": "https://bundles.example/test/hello/1.0.0/app.mvmpkg",
            "archive_sha256": "a" * 64,
            "archive_size": 123,
            "key_id": "b" * 32,
        },
    }


class ApplicationManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "pack-sources" / "test" / "hello"
        self.source.mkdir(parents=True)
        self.packs = self.root / "packs"
        self.output = self.packs / "test" / "hello" / "1.0.0"
        self.write_source()
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def write_source(self, extra=""):
        self.source.joinpath("pack.toml").write_text(
            'version = "1.0.0"\ndescription = "Synthetic app descriptor"\n'
            + extra
            + '[application]\nschema_version = 1\nguest_arch = "aarch64"\n'
            '[application.bundle]\n'
            'source = "https://bundles.example/test/hello/1.0.0/app.mvmpkg"\n'
            f'archive_sha256 = "{"a" * 64}"\narchive_size = 123\n'
            f'key_id = "{"b" * 32}"\n'
        )

    def build(self):
        def fake_sign(_, bundle):
            bundle.write_text("synthetic test signature, not valid")

        with patch.object(builder, "PACKS", self.packs), \
                patch.object(builder, "sign", side_effect=fake_sign) as sign:
            builder.build_one(self.source)
            return sign.call_count

    def validate(self, verify=False):
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.packs):
            validator.validate_manifest(self.output / "manifest.json", verify)
        return list(validator.problems)

    def test_build_validate_and_index_preserve_exact_descriptor(self):
        self.assertEqual(self.build(), 1)
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {"manifest.json", "manifest.sigstore.json"},
        )
        raw = (self.output / "manifest.json").read_bytes()
        self.assertEqual(raw, manifest_bytes(
            "test/hello@1.0.0", "Synthetic app descriptor", application()
        ))
        self.assertEqual(raw, Path(__file__).with_name("application_manifest_v2.json").read_bytes())
        self.assertEqual(json.loads(raw), {
            "schema_version": 2, "kind": "application",
            "reference": "test/hello@1.0.0",
            "description": "Synthetic app descriptor",
            "application": application(),
        })
        self.assertEqual(self.validate(), [])
        index = builder.registry_index(self.packs)
        self.assertEqual(index["schema_version"], 2)
        self.assertEqual(index["packs"][0]["versions"], [{
            "version": "1.0.0", "manifest_sha256": hashlib.sha256(raw).hexdigest()
        }])

    def test_existing_version_requires_verified_signature_and_identical_bytes(self):
        self.build()
        with patch.object(builder, "verify_bundle", return_value=True) as verify:
            self.assertEqual(self.build(), 0)
            self.assertEqual(verify.call_count, 1)
        with patch.object(builder, "verify_bundle", return_value=False):
            with self.assertRaisesRegex(SystemExit, "not trusted"):
                self.build()
        self.source.joinpath("pack.toml").write_text(
            self.source.joinpath("pack.toml").read_text().replace("archive_size = 123", "archive_size = 124")
        )
        with self.assertRaisesRegex(SystemExit, "bump the version"):
            self.build()

    def test_application_cannot_ship_source_or_published_payload(self):
        for name in ("pack", "extra"):
            with self.subTest(name=name):
                extra = self.source / name
                extra.mkdir()
                with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
                    self.build()
                extra.rmdir()
        self.build()
        extra = self.output / "files"
        extra.mkdir()
        self.assertTrue(any("payload" in error for error in self.validate()))
        with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
            self.build()

    def test_application_and_image_metadata_are_exclusive(self):
        for extra in ("[image]\n", "[image_build]\n"):
            with self.subTest(extra=extra):
                self.write_source(extra)
                with self.assertRaisesRegex(SystemExit, "cannot declare image"):
                    builder.parse_pack_toml(self.source / "pack.toml")

    def test_application_version_rejects_build_metadata(self):
        path = self.source / "pack.toml"
        path.write_text(path.read_text().replace('"1.0.0"', '"1.0.0+build"'))
        with self.assertRaisesRegex(SystemExit, "canonical semver"):
            self.build()

    def test_strict_nested_fields_types_and_values(self):
        variants = []
        for key in application():
            value = application()
            del value[key]
            variants.append(value)
        value = application()
        value["files"] = []
        variants.append(value)
        for key in application()["bundle"]:
            value = application()
            del value["bundle"][key]
            variants.append(value)
        value = application()
        value["bundle"]["trust_key"] = "must not enroll keys"
        variants.append(value)
        for key, values in {
            "source": [None, {}, "", "http://example/app", "file:///tmp/app",
                       "https://user@example/app", "https://example/app?",
                       "https://example/app#", "https://example/../app",
                       "https://example\\evil/app", "https://example/\napp",
                       "oci://registry.example/test/app:latest"],
            "archive_sha256": ["A" * 64, "a" * 63, None, "a" * 64 + "\n"],
            "archive_size": [True, False, 0, -1, 1.2, "123", None, 2**64],
            "key_id": ["B" * 32, "b" * 31, None],
        }.items():
            for invalid in values:
                value = application()
                value["bundle"][key] = invalid
                variants.append(value)
        for key, invalid in (("schema_version", True), ("schema_version", 2),
                             ("guest_arch", "amd64"), ("guest_arch", None)):
            value = application()
            value[key] = invalid
            variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_application(value)

    def test_valid_architectures_and_digest_pinned_oci(self):
        for arch in ("aarch64", "x86_64"):
            value = application()
            value["guest_arch"] = arch
            value["bundle"]["source"] = "oci://registry.example/test/hello@sha256:" + "c" * 64
            validate_application(value)

    def test_shared_client_publisher_source_vectors(self):
        fixture = json.loads(Path(__file__).with_name("application_source_vectors.json").read_text())
        self.assertEqual(fixture["schema_version"], 1)
        for case in fixture["cases"]:
            with self.subTest(source=case["source"]):
                if case["valid"]:
                    validate_source(case["source"])
                else:
                    with self.assertRaises(ValueError):
                        validate_source(case["source"])

    def test_validator_rejects_shape_drift_and_wrong_directory(self):
        self.build()
        path = self.output / "manifest.json"
        original = json.loads(path.read_bytes())
        mutations = [
            {"files": []}, {"image": {}}, {"kind": "policy"},
            {"schema_version": True}, {"schema_version": 3},
            {"reference": "test/other@1.0.0"}, {"reference": 3},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                value.update(mutation)
                path.write_text(json.dumps(value))
                self.assertTrue(self.validate())

    def test_application_signature_uses_existing_verifier(self):
        self.build()
        with patch.object(validator, "verify_signature") as verify:
            self.assertEqual(self.validate(verify=True), [])
            verify.assert_called_once_with(
                self.output / "manifest.json", "test/hello@1.0.0"
            )

    def test_duplicate_json_fields_are_rejected(self):
        self.build()
        path = self.output / "manifest.json"
        raw = path.read_text()
        path.write_text(raw.replace('"archive_size": 123', '"archive_size": 124, "archive_size": 123'))
        self.assertTrue(any("duplicate JSON" in error for error in self.validate()))

    def test_symlinks_and_unsigned_files_are_rejected(self):
        self.build()
        outside = self.root / "outside"
        outside.write_text("not part of descriptor")
        extra = self.output / "extra"
        extra.symlink_to(outside)
        self.assertTrue(any("symlink" in error for error in self.validate()))
        with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
            self.build()
        extra.unlink()
        extra.write_text("not part of descriptor")
        self.assertTrue(any("payload" in error for error in self.validate()))

    def test_existing_policy_manifest_bytes_are_unchanged(self):
        root = Path(__file__).resolve().parent.parent
        for path in (root / "packs").glob("*/*/*/manifest.json"):
            manifest = json.loads(path.read_bytes())
            namespace, suffix = manifest["reference"].split("/")
            name, _ = suffix.split("@")
            payload = path.parent / "files" / "pack"
            raw, _ = builder.manifest_bytes(
                manifest["reference"], manifest["description"], payload
            )
            with self.subTest(namespace=namespace, name=name):
                self.assertEqual(raw, path.read_bytes())
