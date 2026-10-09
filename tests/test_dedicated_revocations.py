"""Tests for the dedicated official MVM revocation release channel."""

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "build_dedicated_revocations", ROOT / "scripts" / "build-dedicated-revocations.py"
)
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)


class DedicatedRevocationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
        self.source = (["workflow@example"], ["a" * 64])

    def document(self, previous=None, sequence=None):
        raw = feed.build_document(self.source, previous, self.now)
        if sequence is None:
            return raw
        parsed = json.loads(raw)
        parsed["sequence"] = sequence
        return feed._canonical_document(parsed)

    def test_dedicated_identity_and_issuer_are_exact(self):
        self.assertEqual(
            feed.IDENTITY,
            "https://github.com/tinylabscom/mvm-packs/.github/workflows/registry-pack-revocations.yml@refs/heads/main",
        )
        self.assertEqual(feed.ISSUER, "https://token.actions.githubusercontent.com")

    def test_official_feed_has_thirty_day_maximum_and_exact_expiration(self):
        raw = self.document()
        data = feed.parse_document(raw, self.now)
        self.assertEqual(feed.utc(data["not_after"]) - feed.utc(data["issued_at"]), timedelta(days=30))
        data["not_after"] = feed.timestamp(feed.utc(data["issued_at"]) + timedelta(days=30, seconds=1))
        with self.assertRaisesRegex(feed.RevocationError, "too long"):
            feed.parse_document(feed._canonical_document(data), self.now)
        data["issued_at"] = feed.timestamp(self.now - timedelta(days=30))
        data["not_after"] = feed.timestamp(self.now)
        with self.assertRaisesRegex(feed.RevocationError, "expired"):
            feed.parse_document(feed._canonical_document(data), self.now)

    def test_history_requires_every_signature_and_exact_sequential_growth(self):
        first = self.document()
        first_data = json.loads(first)
        second = feed.build_document(self.source, first_data, self.now)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = []
            for sequence, document in ((1, first), (2, second)):
                path = root / f"revocations-{sequence}.json"
                bundle = root / f"revocations-{sequence}.sigstore.json"
                path.write_bytes(document)
                bundle.write_bytes(b"verified bundle")
                names.extend((path.name, bundle.name))
            (root / feed.DOCUMENT_NAME).write_bytes(second)
            (root / feed.BUNDLE_NAME).write_bytes(b"verified bundle")
            with patch.object(feed, "verify_bundle"):
                self.assertEqual(feed.verify_history(root, names + [feed.DOCUMENT_NAME, feed.BUNDLE_NAME], self.now)["sequence"], 2)
                self.assertEqual(feed.verify_bundle.call_count, 2)
                with self.assertRaisesRegex(feed.RevocationError, "gap"):
                    feed.inventory(["revocations-1.json", "revocations-3.json", "revocations-3.sigstore.json", feed.DOCUMENT_NAME, feed.BUNDLE_NAME])
                with self.assertRaisesRegex(feed.RevocationError, "incomplete"):
                    feed.inventory(["revocations-1.json", feed.DOCUMENT_NAME, feed.BUNDLE_NAME])

    def test_inventory_rejects_u64_max_sequence_without_expanding_range(self):
        sequence = 2**64 - 1
        with self.assertRaisesRegex(feed.RevocationError, "gap"):
            feed.inventory([
                f"revocations-{sequence}.json",
                f"revocations-{sequence}.sigstore.json",
            ])

    def test_history_rejects_missing_or_mismatched_aliases(self):
        raw = self.document()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "revocations-1.json").write_bytes(raw)
            (root / "revocations-1.sigstore.json").write_bytes(b"sig")
            (root / feed.DOCUMENT_NAME).write_bytes(raw + b" ")
            (root / feed.BUNDLE_NAME).write_bytes(b"sig")
            names = ["revocations-1.json", "revocations-1.sigstore.json", feed.DOCUMENT_NAME, feed.BUNDLE_NAME]
            with patch.object(feed, "verify_bundle"):
                with self.assertRaisesRegex(feed.RevocationError, "alias"):
                    feed.verify_history(root, names, self.now)

    def test_unsigned_orphan_requires_exact_source_and_next_sequence(self):
        previous = json.loads(self.document())
        previous["sequence"] = 4
        orphan = self.document(previous)
        self.assertEqual(json.loads(orphan)["sequence"], 5)
        self.assertEqual(json.loads(feed.recover_or_build(self.source, previous, orphan, 5, self.now))["sequence"], 5)
        altered_source = (["injected identity", *self.source[0]], self.source[1])
        with self.assertRaisesRegex(feed.RevocationError, "exactly match"):
            feed.recover_or_build(altered_source, previous, orphan, 5, self.now)
        with self.assertRaisesRegex(feed.RevocationError, "next authenticated"):
            feed.recover_or_build(self.source, previous, orphan, 6, self.now)
        noncanonical = orphan + b" "
        with self.assertRaisesRegex(feed.RevocationError, "canonical"):
            feed.recover_or_build(self.source, previous, noncanonical, 5, self.now)

    def test_bootstrap_document_is_sequence_one_and_orphans_cannot_bootstrap(self):
        raw = feed.build_document(self.source, None, self.now)
        self.assertEqual(json.loads(raw)["sequence"], 1)
        with self.assertRaisesRegex(feed.RevocationError, "cannot bootstrap"):
            feed.recover_or_build(self.source, None, raw, 1, self.now)

    def test_workflow_is_dedicated_least_privilege_and_bootstrap_is_explicit(self):
        workflow = (ROOT / ".github/workflows/registry-pack-revocations.yml").read_text()
        self.assertIn("push:", workflow)
        self.assertIn('"revocations.toml"', workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("authorize_bootstrap", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("revocations.sigstore.json", workflow)
        self.assertIn("revocations-${sequence}.json", workflow)
        self.assertIn(feed.IDENTITY, workflow)
        signer = workflow.split("  sign:\n", 1)[1].split("  publish:\n", 1)[0]
        publisher = workflow.split("  publish:\n", 1)[1]
        self.assertNotIn("contents: write", signer)
        self.assertNotIn("id-token: write", publisher)
        self.assertIn("--certificate-identity", signer)
        self.assertIn("--certificate-identity", publisher)


if __name__ == "__main__":
    unittest.main()
