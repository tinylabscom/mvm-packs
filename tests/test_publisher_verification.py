"""Publisher checks for signed payload completeness and release identity."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, module_name):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_script("build-packs.py", "build_packs_verification")
validator = load_script("validate-packs.py", "validate_packs_verification")


class PublisherVerificationTests(unittest.TestCase):
    def setUp(self):
        validator.problems.clear()

    def test_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            payload.mkdir()
            (payload / "outside").symlink_to(Path(temporary) / "secret")
            with self.assertRaisesRegex(SystemExit, "symlink is not allowed"):
                builder.manifest_bytes("agent/example@1.0.0", "Example", payload)

    def test_undeclared_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "packs" / "agent" / "example" / "1.0.0"
            payload = pack / "files" / "pack"
            payload.mkdir(parents=True)
            policy = payload / "profile.toml"
            policy.write_text("schema_version = 1\n")
            content = policy.read_bytes()
            manifest = {
                "schema_version": 1,
                "reference": "agent/example@1.0.0",
                "description": "Example",
                "files": [{
                    "path": "pack/profile.toml",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }],
            }
            manifest_path = pack / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            (pack / "manifest.sigstore.json").write_text("{}")
            (pack / "unsigned.txt").write_text("extra")
            with patch.object(validator, "ROOT", root), patch.object(validator, "PACKS", root / "packs"):
                validator.validate_manifest(manifest_path)
            self.assertTrue(any("unsigned file" in problem for problem in validator.problems))

    def test_signature_verifies_exact_release_identity_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            manifest.with_name("manifest.sigstore.json").write_text("{}")
            with patch.object(validator, "ROOT", root), patch.object(validator.subprocess, "run") as run:
                run.return_value.returncode = 0
                validator.verify_signature(manifest)
                command = run.call_args.args[0]
                self.assertIn(validator.PUBLISHER_IDENTITY, command)
                self.assertIn(validator.PUBLISHER_ISSUER, command)
                self.assertFalse(validator.problems)

                run.return_value.returncode = 1
                validator.verify_signature(manifest)
            self.assertTrue(any("verification failed" in problem for problem in validator.problems))


if __name__ == "__main__":
    unittest.main()
