"""Revocation feed publication and validation boundaries."""

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("build_revocations", ROOT / "scripts" / "build-revocations.py")
revocations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(revocations)
validator_spec = importlib.util.spec_from_file_location("validate_packs_revocations", ROOT / "scripts" / "validate-packs.py")
validator = importlib.util.module_from_spec(validator_spec)
validator_spec.loader.exec_module(validator)


class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)

    def document(self, *, previous=None, source=([], [])):
        return revocations.build_document(source, previous, self.now)

    def test_initial_document_matches_client_schema_and_expires_within_48_hours(self):
        raw = self.document()
        parsed = revocations.parse_document(raw, self.now)
        self.assertEqual(parsed["schema_version"], 1)
        self.assertEqual(parsed["sequence"], 1)
        self.assertLessEqual(
            revocations.utc(parsed["not_after"]) - revocations.utc(parsed["issued_at"]),
            timedelta(hours=48),
        )
        self.assertEqual(parsed["revoked_identities"], [])
        self.assertEqual(parsed["revoked_manifests"], [])

    def test_source_rejects_unknown_schema_duplicate_and_malformed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "revocations.toml"
            for content in (
                'schema_version = 2\nrevoked_identities = []\nrevoked_manifests = []\n',
                'schema_version = 1\nrevoked_identities = ["same", "same"]\nrevoked_manifests = []\n',
                'schema_version = 1\nrevoked_identities = []\nrevoked_manifests = ["BAD"]\n',
                'schema_version = 1\nrevoked_identities = []\nrevoked_manifests = []\nextra = 1\n',
            ):
                path.write_text(content)
                with self.assertRaises(revocations.RevocationError):
                    revocations.read_source(path)

    def test_expired_future_or_overlong_documents_fail_closed(self):
        raw = self.document()
        with self.assertRaisesRegex(revocations.RevocationError, "expired"):
            revocations.parse_document(raw, self.now + timedelta(hours=36))
        with self.assertRaisesRegex(revocations.RevocationError, "future"):
            revocations.parse_document(raw, self.now - timedelta(seconds=1))
        parsed = json.loads(raw)
        parsed["not_after"] = revocations.timestamp(self.now + timedelta(hours=49))
        with self.assertRaisesRegex(revocations.RevocationError, "too long"):
            revocations.parse_document(json.dumps(parsed).encode(), self.now)

    def test_next_document_advances_and_cannot_remove_revocation(self):
        former = json.loads(self.document(source=(["old identity"], ["a" * 64])))
        next_raw = self.document(previous=former, source=(["old identity", "new identity"], ["a" * 64]))
        self.assertEqual(revocations.parse_document(next_raw, self.now)["sequence"], 2)
        with self.assertRaisesRegex(revocations.RevocationError, "cannot remove"):
            self.document(previous=former)

    def test_manifest_digest_and_identity_duplicates_are_refused(self):
        parsed = json.loads(self.document())
        parsed["revoked_identities"] = ["a", "a"]
        with self.assertRaisesRegex(revocations.RevocationError, "duplicate"):
            revocations.parse_document(json.dumps(parsed).encode(), self.now)
        parsed["revoked_identities"] = []
        parsed["revoked_manifests"] = ["b" * 64, "b" * 64]
        with self.assertRaisesRegex(revocations.RevocationError, "duplicate"):
            revocations.parse_document(json.dumps(parsed).encode(), self.now)

    def test_duplicate_json_fields_are_refused(self):
        raw = self.document().decode().replace('"sequence": 1', '"sequence": 1, "sequence": 2')
        with self.assertRaisesRegex(revocations.RevocationError, "repeats"):
            revocations.parse_document(raw.encode(), self.now)

    def test_publish_refuses_rollback_equivocation_and_revocation_removal(self):
        previous = json.loads(self.document(source=(["old"], [])))
        next_document = json.loads(self.document(previous=previous, source=(["old"], [])))
        revocations.check_advance(next_document, previous)
        for sequence in (0, 1, 3):
            candidate = dict(next_document, sequence=sequence)
            with self.assertRaisesRegex(revocations.RevocationError, "sequence"):
                revocations.check_advance(candidate, previous)
        with self.assertRaisesRegex(revocations.RevocationError, "rolled back"):
            revocations.check_advance(dict(next_document, revoked_identities=[]), previous)

    def test_signature_requires_exact_current_release_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, bundle = root / "revocations.json", root / "revocations.sigstore.json"
            document.write_bytes(self.document())
            bundle.write_text("{}")
            with patch.object(revocations.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0)
                revocations.verify_bundle(document, bundle)
                command = run.call_args.args[0]
                self.assertIn(revocations.CURRENT_IDENTITY, command)
                self.assertIn(revocations.PUBLISHER_ISSUER, command)
                run.return_value = subprocess.CompletedProcess([], 1)
                with self.assertRaisesRegex(revocations.RevocationError, "signature"):
                    revocations.verify_bundle(document, bundle)

    def test_publish_validator_refuses_stale_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            packs = Path(temporary) / "packs"
            manifest = packs / "runtime" / "example" / "1.0.0" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("{}")
            (packs / "index.json").write_text(json.dumps({
                "schema_version": 1,
                "packs": [{"namespace": "runtime", "name": "example", "description": "Example", "versions": ["1.0.0"]}],
            }))
            document = packs / "revocations.json"
            expired_at = datetime.now(timezone.utc) - timedelta(days=3)
            document.write_bytes(revocations.build_document(([], []), None, expired_at))
            bundle = packs / "revocations.sigstore.json"
            bundle.write_text("{}")
            with patch.object(validator, "PACKS", packs), \
                    patch.object(validator, "REVOCATIONS", document), \
                    patch.object(validator, "REVOCATION_BUNDLE", bundle), \
                    patch.object(validator, "validate_manifest"):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                    validator.main(["--verify-signatures", "--require-revocations"])
            self.assertEqual(result.exception.code, 1)
            self.assertTrue(any("expired" in problem for problem in validator.problems))

    def test_workflow_refreshes_and_separates_signing_from_publish(self):
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text()
        self.assertIn('cron: "17 */12 * * *"', workflow)
        self.assertIn("python3 scripts/build-revocations.py", workflow)
        self.assertIn("--require-revocations", workflow)
        sign = workflow.split("  sign:\n", 1)[1].split("  publish:\n", 1)[0]
        publish = workflow.split("  publish:\n", 1)[1]
        self.assertIn("id-token: write", sign)
        self.assertNotIn("contents: write", sign)
        self.assertIn("contents: write", publish)
        self.assertNotIn("id-token: write", publish)
        self.assertIn("--check-advance-from", publish)


if __name__ == "__main__":
    unittest.main()
