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

    def test_new_feed_has_thirty_six_hour_window_and_exact_expiration(self):
        raw = self.document()
        data = feed.parse_document(raw, self.now, maximum_validity=feed.VALIDITY)
        self.assertEqual(feed.utc(data["not_after"]) - feed.utc(data["issued_at"]), timedelta(hours=36))
        data["not_after"] = feed.timestamp(feed.utc(data["issued_at"]) + timedelta(hours=36, seconds=1))
        with self.assertRaisesRegex(feed.RevocationError, "too long"):
            feed.parse_document(feed._canonical_document(data), self.now, maximum_validity=feed.VALIDITY)
        data["issued_at"] = feed.timestamp(self.now - timedelta(days=30))
        data["not_after"] = feed.timestamp(self.now)
        with self.assertRaisesRegex(feed.RevocationError, "expired"):
            feed.parse_document(feed._canonical_document(data), self.now)

    def test_old_thirty_day_history_is_preserved_but_not_new_candidate_authority(self):
        old = json.loads(self.document())
        old["not_after"] = feed.timestamp(self.now + timedelta(days=30))
        raw = feed._canonical_document(old)
        feed.parse_document(raw, self.now, allow_expired=True)
        old["not_after"] = feed.timestamp(self.now + timedelta(days=30, seconds=1))
        with self.assertRaisesRegex(feed.RevocationError, "too long"):
            feed.parse_document(feed._canonical_document(old), self.now, allow_expired=True)
        with self.assertRaisesRegex(feed.RevocationError, "too long"):
            feed.parse_document(raw, self.now, maximum_validity=feed.VALIDITY)
        following = json.loads(feed.build_document(self.source, json.loads(raw), self.now))
        self.assertEqual(following["sequence"], 2)
        self.assertEqual(feed.utc(following["not_after"]) - feed.utc(following["issued_at"]), timedelta(hours=36))

    def test_long_window_orphan_cannot_be_resigned_under_new_candidate_contract(self):
        previous = json.loads(self.document())
        for window in (timedelta(hours=36, seconds=1), timedelta(hours=48), timedelta(days=30)):
            orphan = json.loads(self.document(previous))
            orphan["not_after"] = feed.timestamp(self.now + window)
            with self.subTest(window=window), self.assertRaisesRegex(feed.RevocationError, "too long"):
                feed.recover_or_build(
                    self.source, previous, feed._canonical_document(orphan), 2, self.now
                )

    def test_history_verification_accepts_expired_thirty_day_prefix_and_new_short_head(self):
        previous = json.loads(self.document())
        previous["issued_at"] = feed.timestamp(self.now - timedelta(days=31))
        previous["not_after"] = feed.timestamp(self.now - timedelta(days=1))
        old = feed._canonical_document(previous)
        new = feed.build_document(self.source, previous, self.now)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = []
            for sequence, document in ((1, old), (2, new)):
                path = root / f"revocations-{sequence}.json"
                bundle = root / f"revocations-{sequence}.sigstore.json"
                path.write_bytes(document)
                bundle.write_bytes(b"unit signature seam")
                names.extend((path.name, bundle.name))
            (root / feed.DOCUMENT_NAME).write_bytes(new)
            (root / feed.BUNDLE_NAME).write_bytes(b"unit signature seam")
            with patch.object(feed, "verify_bundle") as verify:
                head = feed.verify_history(root, names + [feed.DOCUMENT_NAME, feed.BUNDLE_NAME], self.now)
                self.assertEqual(verify.call_count, 2)
            self.assertEqual(head["sequence"], 2)
            self.assertEqual(feed.utc(head["not_after"]) - feed.utc(head["issued_at"]), timedelta(hours=36))

    def test_candidate_cli_rejects_long_window_after_signature_verification(self):
        previous = self.document()
        candidate = json.loads(self.document(json.loads(previous)))
        candidate["not_after"] = feed.timestamp(self.now + timedelta(days=30))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document, bundle, source = root / "candidate.json", root / "candidate.bundle", root / "source.toml"
            document.write_bytes(feed._canonical_document(candidate))
            bundle.write_bytes(b"unit signature seam")
            source.write_text(
                'schema_version = 1\nrevoked_identities = ["workflow@example"]\n'
                'revoked_manifests = ["' + "a" * 64 + '"]\n'
            )
            names = root / "assets.json"
            names.write_text("[]")
            with patch.object(feed, "verify_bundle") as verify:
                with self.assertRaisesRegex(SystemExit, "too long"):
                    feed.main([
                        "--check-candidate", "--history", str(root), "--asset-names", str(names),
                        "--document", str(document), "--bundle", str(bundle),
                        "--source", str(source), "--now", feed.timestamp(self.now),
                    ])
                verify.assert_called_once_with(document, bundle)

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
        self.assertIn("timeout-minutes: 15", signer)
        self.assertIn("timeout-minutes: 15", publisher)
        self.assertIn("--certificate-identity", signer)
        self.assertIn("--certificate-identity", publisher)


if __name__ == "__main__":
    unittest.main()
