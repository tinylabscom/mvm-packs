"""The former publisher is accepted only for pinned historical manifests."""

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from publisher_identity import accepts_former, is_historical_manifest


class PublisherIdentityTests(unittest.TestCase):
    def test_only_the_nine_published_manifests_are_historical(self):
        manifests = sorted((ROOT / "packs").glob("*/*/*/manifest.json"))
        historical = 0
        for manifest in manifests:
            content = manifest.read_bytes()
            reference = json.loads(content)["reference"]
            historical += is_historical_manifest(reference, content)
            self.assertFalse(is_historical_manifest(reference, content + b" "))
        self.assertEqual(historical, 9)

    def test_cutoff_is_exclusive_and_cannot_authorize_another_namespace(self):
        manifest = sorted((ROOT / "packs").glob("*/*/*/manifest.json"))[0]
        content = manifest.read_bytes()
        reference = json.loads(content)["reference"]
        before = datetime(2026, 11, 5, 23, 59, 59, tzinfo=timezone.utc)
        cutoff = datetime(2026, 11, 6, 0, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(accepts_former(reference, content, before))
        self.assertFalse(accepts_former(reference, content, cutoff))
        self.assertFalse(accepts_former("community/example@1.0.0", content, before))


if __name__ == "__main__":
    unittest.main()
