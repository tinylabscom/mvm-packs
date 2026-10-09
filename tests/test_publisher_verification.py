"""Publisher checks for signed payload completeness and release identity."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


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

    def test_source_only_image_manifest_is_not_releasable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "packs" / "runtime" / "python" / "1.0.0"
            image_dir = pack / "files" / "pack" / "image"
            image_dir.mkdir(parents=True)
            (image_dir / "mvm.toml").write_text('flake = "."\n')
            (image_dir / "flake.nix").write_text("{}\n")
            (image_dir / "flake.lock").write_text("{}\n")
            encoded, _ = builder.manifest_bytes(
                "runtime/python@1.0.0", "Python", pack / "files" / "pack",
                {"manifest": "pack/image/mvm.toml"},
            )
            manifest = pack / "manifest.json"
            manifest.write_bytes(encoded)
            (pack / "manifest.sigstore.json").write_text("{}")
            with patch.object(validator, "ROOT", root), \
                    patch.object(validator, "PACKS", root / "packs"):
                validator.validate_manifest(manifest)
            self.assertTrue(any("built image digest" in problem for problem in validator.problems))

    def test_built_image_requires_signature_and_public_release_verification(self):
        from tests.test_pack_images import PackImageTests

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "packs" / "runtime" / "python" / "1.0.0"
            payload = pack / "files" / "pack"
            payload.mkdir(parents=True)
            (payload / "group.toml").write_text('description = "Python"\n')
            image = PackImageTests().built_image()
            encoded, _ = builder.manifest_bytes(
                "runtime/python@1.0.0", "Python", payload, image,
            )
            manifest = pack / "manifest.json"
            manifest.write_bytes(encoded)
            (pack / "manifest.sigstore.json").write_text("bundle")
            with patch.object(validator, "ROOT", root), \
                    patch.object(validator, "PACKS", root / "packs"), \
                    patch.object(validator, "verify_published_image") as public:
                validator.validate_manifest(manifest)
                self.assertTrue(any("requires publisher signature" in problem
                                    for problem in validator.problems))
                public.assert_not_called()
                validator.problems.clear()
                with patch.object(validator, "verify_signature") as signature:
                    validator.validate_manifest(manifest, verify_signatures=True)
                signature.assert_called_once()
                public.assert_called_once_with(image, "runtime/python@1.0.0")
                self.assertFalse(validator.problems)
                validator.problems.clear()
                public.side_effect = validator.ImageReleaseError("release bytes differ")
                with patch.object(validator, "verify_signature"):
                    validator.validate_manifest(manifest, verify_signatures=True)
                self.assertTrue(any("release bytes differ" in problem
                                    for problem in validator.problems))
                validator.problems.clear()
                public.reset_mock(side_effect=True)
                with patch.object(validator, "verify_signature",
                                  side_effect=lambda *_: validator.problems.append(
                                      "publisher signature invalid")):
                    validator.validate_manifest(manifest, verify_signatures=True)
                public.assert_not_called()
                self.assertIn("publisher signature invalid", validator.problems)

    def test_policy_only_manifest_still_validates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, published = self.make_source_and_published_pack(root)
            self.assertTrue(source.is_dir())
            with patch.object(validator, "ROOT", root), \
                    patch.object(validator, "PACKS", root / "packs"):
                validator.validate_manifest(published / "manifest.json")
            self.assertFalse(validator.problems)

    def test_pr_validation_checks_signatures_and_public_release_bytes(self):
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text()
        self.assertIn("cosign verify-blob cosign-linux-amd64", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn(
            "scripts/validate-packs.py --verify-signatures --require-revocations",
            workflow,
        )

    def test_public_image_verifier_requires_authenticated_release_access(self):
        from tests.test_pack_images import PackImageTests

        image = PackImageTests().built_image()
        with patch.dict(validator.os.environ, {"GITHUB_TOKEN": ""}):
            with self.assertRaisesRegex(validator.ImageReleaseError,
                                        "GITHUB_TOKEN is required"):
                validator.verify_published_image(image, "runtime/python@1.0.0")

    def test_signature_verifies_exact_release_identity_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            manifest.with_name("manifest.sigstore.json").write_text("{}")
            with patch.object(validator, "ROOT", root), patch.object(validator.subprocess, "run") as run:
                run.return_value.returncode = 0
                validator.verify_signature(manifest, "agent/example@1.0.0")
                command = run.call_args.args[0]
                self.assertIn(validator.PUBLISHER_IDENTITY, command)
                self.assertIn(validator.PUBLISHER_ISSUER, command)
                self.assertFalse(validator.problems)

                run.return_value.returncode = 1
                validator.verify_signature(manifest, "agent/example@1.0.0")
            self.assertTrue(any("verification failed" in problem for problem in validator.problems))

    def test_historical_signature_uses_only_the_pinned_former_identity(self):
        manifest = sorted((ROOT / "packs").glob("*/*/*/manifest.json"))[0]
        reference = json.loads(manifest.read_text())["reference"]
        with patch.object(validator.subprocess, "run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 1),
                subprocess.CompletedProcess([], 0),
            ]
            validator.verify_signature(manifest, reference)
        self.assertEqual(
            [
                call.args[0][call.args[0].index("--certificate-identity") + 1]
                for call in run.call_args_list
            ],
            [validator.PUBLISHER_IDENTITY, validator.FORMER_IDENTITY],
        )
        self.assertFalse(validator.problems)

    def test_unpinned_manifest_never_tries_the_former_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text('{}')
            manifest.with_name("manifest.sigstore.json").write_text('{}')
            with patch.object(validator, "ROOT", root), \
                    patch.object(validator.subprocess, "run") as run:
                run.return_value.returncode = 1
                validator.verify_signature(manifest, "agent/example@1.0.0")
            self.assertEqual(run.call_count, 1)
            self.assertTrue(validator.problems)

    def make_source_and_published_pack(self, root):
        source = root / "pack-sources" / "runtime" / "example"
        payload = source / "pack"
        payload.mkdir(parents=True)
        (source / "pack.toml").write_text('version = "1.0.0"\ndescription = "Example"\n')
        (payload / "profile.toml").write_text("schema_version = 1\n")
        published = root / "packs" / "runtime" / "example" / "1.0.0"
        (published / "files" / "pack").mkdir(parents=True)
        (published / "files" / "pack" / "profile.toml").write_bytes(
            (payload / "profile.toml").read_bytes()
        )
        manifest, _ = builder.manifest_bytes("runtime/example@1.0.0", "Example", payload)
        (published / "manifest.json").write_bytes(manifest)
        (published / "manifest.sigstore.json").write_text("{}")
        return source, published

    def test_current_identity_skips_resigning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.make_source_and_published_pack(root)
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "verify_bundle", return_value=True) as verify, \
                    patch.object(builder, "sign") as sign:
                builder.build_one(source)
            verify.assert_called_once()
            self.assertEqual(verify.call_args.args[2], builder.CURRENT_IDENTITY)
            sign.assert_not_called()

    def test_bundle_verification_uses_exact_identity_and_issuer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            bundle = root / "manifest.sigstore.json"
            manifest.write_text("{}")
            bundle.write_text("{}")
            with patch.object(builder.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertTrue(builder.verify_bundle(manifest, bundle, builder.FORMER_IDENTITY))
                command = run.call_args.args[0]
                self.assertIn(builder.FORMER_IDENTITY, command)
                self.assertIn(builder.PUBLISHER_ISSUER, command)
                run.return_value.returncode = 1
                self.assertFalse(builder.verify_bundle(manifest, bundle, builder.FORMER_IDENTITY))

    def test_pinned_former_identity_is_preserved_during_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, published = self.make_source_and_published_pack(root)
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "is_historical_manifest", return_value=True), \
                    patch.object(builder, "accepts_former", return_value=True), \
                    patch.object(builder, "verify_bundle", side_effect=[False, True]) as verify, \
                    patch.object(builder, "sign") as sign:
                builder.build_one(source)
            self.assertEqual(
                [call.args[2] for call in verify.call_args_list],
                [builder.CURRENT_IDENTITY, builder.FORMER_IDENTITY],
            )
            sign.assert_not_called()
            self.assertTrue((published / "manifest.json").is_file())

    def test_pinned_former_identity_is_resigned_after_cutoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.make_source_and_published_pack(root)
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "is_historical_manifest", return_value=True), \
                    patch.object(builder, "accepts_former", return_value=False), \
                    patch.object(builder, "verify_bundle", side_effect=[False, True]), \
                    patch.object(builder, "sign") as sign:
                builder.build_one(source)
            sign.assert_called_once()

    def test_untrusted_signature_is_not_resigned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.make_source_and_published_pack(root)
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "verify_bundle", return_value=False), \
                    patch.object(builder, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "signature is not trusted"):
                    builder.build_one(source)
            sign.assert_not_called()

    def test_drifted_payload_is_not_resigned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, published = self.make_source_and_published_pack(root)
            (published / "files" / "pack" / "profile.toml").write_text("changed")
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "verify_bundle") as verify, \
                    patch.object(builder, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "published payload differs"):
                    builder.build_one(source)
            verify.assert_not_called()
            sign.assert_not_called()

    def test_published_symlink_is_not_resigned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, published = self.make_source_and_published_pack(root)
            (published / "files" / "pack" / "profile.toml").unlink()
            (published / "files" / "pack" / "profile.toml").symlink_to(
                source / "pack" / "profile.toml"
            )
            with patch.object(builder, "PACKS", root / "packs"), \
                    patch.object(builder, "verify_bundle") as verify, \
                    patch.object(builder, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "contains a symlink"):
                    builder.build_one(source)
            verify.assert_not_called()
            sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
