"""A built pack enters the registry only after verified release readback."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "publish_image_pack", ROOT / "scripts" / "publish-image-pack.py"
)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class RegistryImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "pack-sources" / "runtime" / "python"
        (self.source / "pack").mkdir(parents=True)
        (self.source / "pack" / "group.toml").write_text('description = "Python"\n')
        self.base = {
            "repository": "tinylabscom/mvm-images",
            "release_tag": "image-set/v0.2.4",
            "manifest_sha256": "a" * 64,
        }
        (self.source / "pack.toml").write_text(
            'version = "1.1.0"\ndescription = "Python runtime"\n'
            '[image_build]\nschema_version = 1\nplatform = "linux/x86_64"\n'
            '[image_build.base_set]\nrepository = "tinylabscom/mvm-images"\n'
            'release_tag = "image-set/v0.2.4"\n'
            f'manifest_sha256 = "{self.base["manifest_sha256"]}"\n'
            '[image_build.release]\nrepository = "tinylabscom/mvm-packs"\n'
            'tag = "pack-runtime-python-v1.1.0"\n'
        )
        self.lock = self.root / "images.lock"
        self.lock.write_text("lock")
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.packs = self.root / "packs"
        self.environment = {
            "GITHUB_REPOSITORY": "tinylabscom/mvm-packs",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": (
                "tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
            ),
            "GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "b" * 40,
        }
        self.descriptor = {
            "schema_version": 2,
            "platform": "linux/x86_64",
            "base_set": self.base,
            "release": {
                "repository": "tinylabscom/mvm-packs",
                "tag": "pack-runtime-python-v1.1.0",
            },
            "assets": {
                role: {"name": name, "sha256": "c" * 64, "size": 1}
                for role, name in publisher.builder.BUILT_IMAGE_ASSETS.items()
            },
        }

    def fake_stage(self, _evidence, _reference, _source, _lock, output):
        output.mkdir()
        (output / "image-descriptor.json").write_text(json.dumps(self.descriptor))

    def fake_sign(self, _manifest, bundle):
        bundle.write_text("signed")

    def call_publish(self):
        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                mock.patch.object(publisher.uploader, "verify_published") as verified, \
                mock.patch.object(publisher.signer, "sign_and_verify",
                                  side_effect=self.fake_sign) as signed, \
                mock.patch.object(publisher.builder, "PACKS", self.packs):
            publisher.publish(self.source, self.evidence, self.lock,
                              self.environment, object())
        return verified, signed

    def test_verified_release_is_signed_into_immutable_registry_version(self):
        verified, signed = self.call_publish()
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(signed.call_count, 1)
        out = self.packs / "runtime" / "python" / "1.1.0"
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["image"], self.descriptor)
        self.assertEqual((out / "files" / "pack" / "group.toml").read_text(),
                         'description = "Python"\n')
        self.assertIn("1.1.0", json.dumps(json.loads(
            (self.packs / "index.json").read_text())))

    def test_failed_release_check_leaves_no_registry_version(self):
        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                mock.patch.object(publisher.uploader, "verify_published",
                                  side_effect=publisher.uploader.UploadError("wrong bytes")), \
                mock.patch.object(publisher.signer, "sign_and_verify") as signed, \
                mock.patch.object(publisher.builder, "PACKS", self.packs):
            with self.assertRaisesRegex(publisher.PublishError, "wrong bytes"):
                publisher.publish(self.source, self.evidence, self.lock,
                                  self.environment, object())
        signed.assert_not_called()
        self.assertFalse((self.packs / "runtime" / "python" / "1.1.0").exists())

    def test_existing_version_and_linked_payload_refuse_without_signing(self):
        out = self.packs / "runtime" / "python" / "1.1.0"
        out.mkdir(parents=True)
        (out / "operator-data").write_bytes(b"keep")
        with self.assertRaisesRegex(publisher.PublishError, "already exists"):
            self.call_publish()
        self.assertEqual((out / "operator-data").read_bytes(), b"keep")
        (out / "operator-data").unlink()
        out.rmdir()
        policy = self.source / "pack" / "group.toml"
        policy.unlink()
        policy.symlink_to(self.lock)
        with self.assertRaisesRegex(publisher.PublishError, "symlink"):
            self.call_publish()
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
