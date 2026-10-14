"""The sole root pack catalog pins exact published manifest bytes."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder, validator


class PackIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.packs = self.root / "packs"
        for version, description in (("1.0.0", "Old"), ("1.0.1", "Claude policy")):
            directory = self.packs / "agent" / "claude" / version
            directory.mkdir(parents=True)
            (directory / "manifest.json").write_text(json.dumps({
                "schema_version": 1,
                "reference": f"agent/claude@{version}",
                "description": description,
                "files": [],
            }))
        self.expected = {
            "schema_version": 2,
            "packs": [{
                "namespace": "agent",
                "name": "claude",
                "description": "Claude policy",
                "versions": [
                    {
                        "version": version,
                        "manifest_sha256": hashlib.sha256(
                            (self.packs / "agent" / "claude" / version / "manifest.json").read_bytes()
                        ).hexdigest(),
                    }
                    for version in ("1.0.1", "1.0.0")
                ],
            }],
        }
        self.write_indexes(self.expected)
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def write_indexes(self, value):
        (self.root / "index.json").write_text(json.dumps(value))

    def validate(self):
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.packs):
            validator.validate_index()
        return list(validator.problems)

    def test_builder_generates_only_root_index_from_published_manifests(self):
        # A future source version must not become a discoverable published pack.
        source = self.root / "pack-sources" / "agent" / "claude"
        source.mkdir(parents=True)
        (source / "pack.toml").write_text('version = "2.0.0"\n')
        with patch.object(builder, "PACKS", self.packs):
            builder.rebuild_index()
        self.assertFalse((self.packs / "index.json").exists())
        self.assertEqual(json.loads((self.root / "index.json").read_text()), self.expected)
        self.assertFalse(self.validate())

    def test_catalog_drift_and_malformed_pins_are_rejected(self):
        changes = {
            "omitted pack": lambda index: index.update(packs=[]),
            "omitted version": lambda index: index["packs"][0]["versions"].pop(),
            "nonexistent version": lambda index: index["packs"][0]["versions"][0].update(version="2.0.0"),
            "duplicate pack": lambda index: index["packs"].append(copy.deepcopy(index["packs"][0])),
            "duplicate version": lambda index: index["packs"][0]["versions"].append(
                copy.deepcopy(index["packs"][0]["versions"][0])
            ),
            "stale description": lambda index: index["packs"][0].update(description="Old"),
            "extra field": lambda index: index["packs"][0].update(signature="not authority"),
            "wrong schema type": lambda index: index.update(schema_version=True),
            "legacy schema": lambda index: index.update(schema_version=1),
            "legacy version": lambda index: index["packs"][0].update(versions=["1.0.1"]),
            "missing digest": lambda index: index["packs"][0]["versions"][0].pop("manifest_sha256"),
            "wrong digest": lambda index: index["packs"][0]["versions"][0].update(manifest_sha256="0" * 64),
            "uppercase digest": lambda index: index["packs"][0]["versions"][0].update(manifest_sha256="A" * 64),
            "short digest": lambda index: index["packs"][0]["versions"][0].update(manifest_sha256="a"),
            "extra version field": lambda index: index["packs"][0]["versions"][0].update(signature="untrusted"),
        }
        for label, change in changes.items():
            with self.subTest(change=label):
                value = copy.deepcopy(self.expected)
                change(value)
                self.write_indexes(value)
                problems = self.validate()
                self.assertEqual(len(problems), 1)
                self.assertIn("must exactly match", problems[0])

    def test_missing_and_malformed_indexes_fail_cleanly(self):
        path = self.root / "index.json"
        for content in (None, "{", "[]", "null"):
            with self.subTest(content=content):
                self.write_indexes(self.expected)
                if content is None:
                    path.unlink()
                else:
                    path.write_text(content)
                self.assertEqual(len(self.validate()), 1)

    def test_checked_in_index_matches_published_manifests(self):
        validator.validate_index()
        self.assertFalse(validator.problems)

    def test_obsolete_duplicate_catalog_is_rejected(self):
        (self.packs / "index.json").write_text(json.dumps(self.expected))
        self.assertIn("obsolete duplicate", self.validate()[0])

    def test_manifest_pin_hashes_exact_bytes_not_reserialized_json(self):
        path = self.packs / "agent" / "claude" / "1.0.1" / "manifest.json"
        original = path.read_bytes()
        path.write_bytes(original + b"\n\n")
        self.assertTrue(self.validate())
        changed = builder.registry_index(self.packs)
        pin = changed["packs"][0]["versions"][0]["manifest_sha256"]
        self.assertEqual(pin, hashlib.sha256(original + b"\n\n").hexdigest())
        self.assertNotEqual(pin, self.expected["packs"][0]["versions"][0]["manifest_sha256"])
        self.write_indexes(changed)
        self.assertFalse(self.validate())

    def test_publisher_transfers_and_commits_root_index(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/publish.yml").read_text()
        self.assertIn("path: |\n            index.json\n            packs/", workflow)
        self.assertIn("name: signed-packs\n          path: .\n", workflow)
        self.assertIn("git add index.json packs/", workflow)
        self.assertNotIn("packs/index.json", workflow)
        validation = (root / ".github/workflows/validate.yml").read_text()
        self.assertIn('- "index.json"', validation)
        self.assertIn('- "packs/**"', validation)
