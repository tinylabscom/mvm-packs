"""The root pack catalog and compatibility copy describe published bytes."""

import copy
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
            "schema_version": 1,
            "packs": [{
                "namespace": "agent",
                "name": "claude",
                "description": "Claude policy",
                "versions": ["1.0.1", "1.0.0"],
            }],
        }
        self.write_indexes(self.expected)
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def write_indexes(self, value):
        for path in (self.root / "index.json", self.packs / "index.json"):
            path.write_text(json.dumps(value))

    def validate(self):
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.packs):
            validator.validate_indexes()
        return list(validator.problems)

    def test_builder_generates_both_indexes_from_published_manifests(self):
        # A future source version must not become a discoverable published pack.
        source = self.root / "pack-sources" / "agent" / "claude"
        source.mkdir(parents=True)
        (source / "pack.toml").write_text('version = "2.0.0"\n')
        with patch.object(builder, "PACKS", self.packs):
            builder.rebuild_index()
        self.assertEqual(
            (self.root / "index.json").read_bytes(),
            (self.packs / "index.json").read_bytes(),
        )
        self.assertEqual(json.loads((self.root / "index.json").read_text()), self.expected)
        self.assertFalse(self.validate())

    def test_catalog_drift_is_rejected_in_either_copy(self):
        changes = {
            "omitted pack": lambda index: index.update(packs=[]),
            "omitted version": lambda index: index["packs"][0]["versions"].pop(),
            "nonexistent version": lambda index: index["packs"][0]["versions"].append("2.0.0"),
            "duplicate pack": lambda index: index["packs"].append(copy.deepcopy(index["packs"][0])),
            "duplicate version": lambda index: index["packs"][0]["versions"].append("1.0.1"),
            "stale description": lambda index: index["packs"][0].update(description="Old"),
            "extra field": lambda index: index["packs"][0].update(signature="not authority"),
            "wrong schema type": lambda index: index.update(schema_version=True),
        }
        for path in (self.root / "index.json", self.packs / "index.json"):
            for label, change in changes.items():
                with self.subTest(path=path, change=label):
                    self.write_indexes(self.expected)
                    value = copy.deepcopy(self.expected)
                    change(value)
                    path.write_text(json.dumps(value))
                    problems = self.validate()
                    self.assertEqual(len(problems), 1)
                    self.assertIn(path.relative_to(self.root).as_posix(), problems[0])
                    self.assertIn("must exactly match", problems[0])

    def test_missing_and_malformed_indexes_fail_cleanly(self):
        for path in (self.root / "index.json", self.packs / "index.json"):
            for content in (None, "{", "[]", "null"):
                with self.subTest(path=path, content=content):
                    self.write_indexes(self.expected)
                    if content is None:
                        path.unlink()
                    else:
                        path.write_text(content)
                    self.assertEqual(len(self.validate()), 1)

    def test_checked_in_indexes_match_published_manifests(self):
        validator.validate_indexes()
        self.assertFalse(validator.problems)

    def test_publisher_transfers_and_commits_both_indexes(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/publish.yml").read_text()
        self.assertIn("path: |\n            index.json\n            packs/", workflow)
        self.assertIn("name: signed-packs\n          path: .\n", workflow)
        self.assertIn("git add index.json packs/", workflow)
        validation = (root / ".github/workflows/validate.yml").read_text()
        self.assertIn('- "index.json"', validation)
        self.assertIn('- "packs/**"', validation)
