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

    def test_resign_replaces_old_bundle_without_changing_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pack-sources" / "agent" / "example"
            payload = source / "pack"
            payload.mkdir(parents=True)
            (source / "pack.toml").write_text('version = "1.0.0"\ndescription = "Example"\n')
            (payload / "profile.toml").write_text("schema_version = 1\n")
            output = root / "packs" / "agent" / "example" / "1.0.0"
            output.mkdir(parents=True)
            manifest, _ = builder.manifest_bytes("agent/example@1.0.0", "Example", payload)
            (output / "manifest.json").write_bytes(manifest)
            (output / "manifest.sigstore.json").write_text('{"verificationMaterial": {"old": true}}')

            def sign_new(_, bundle):
                bundle.write_text('{"verificationMaterial": {"new": true}}')

            with patch.object(builder, "PACKS", root / "packs"), patch.object(builder, "sign", side_effect=sign_new) as sign:
                builder.build_one(source)
                sign.assert_not_called()
                builder.build_one(source, resign=True)
                sign.assert_called_once()

            self.assertEqual((output / "manifest.json").read_bytes(), manifest)
            self.assertIn('"new"', (output / "manifest.sigstore.json").read_text())

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
                self.assertIn(
                    "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
                    command,
                )
                self.assertNotIn(
                    "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main",
                    command,
                )
                self.assertIn(validator.PUBLISHER_ISSUER, command)
                self.assertFalse(validator.problems)

                run.return_value.returncode = 1
                validator.verify_signature(manifest)
            self.assertTrue(any("verification failed" in problem for problem in validator.problems))


if __name__ == "__main__":
    unittest.main()
