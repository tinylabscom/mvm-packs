"""Real preparation interfaces with MOCK signatures: no live signing or network."""

import hashlib
import json
import unittest
from unittest import mock

from tests import test_publish_image_pack as registry_tests
from tests import test_sign_composed_image as signing_tests


class PrivateEvidenceTests(unittest.TestCase):
    def setUp(self):
        # Reuse the real signed-evidence fixture producer, replacing ONLY its
        # signature operation. Hash stand-ins are not cryptographic signatures.
        self.fixture = signing_tests.SigningTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        with mock.patch.object(signing_tests.signer, "sign_and_verify",
                               side_effect=self.fixture.fake_sign):
            self.fixture.prepare()
        payload = self.fixture.source / "pack"
        payload.mkdir()
        (payload / "group.toml").write_text('description = "Python"\n')
        (payload / "nested").mkdir()
        (payload / "nested" / "policy.toml").write_text('description = "Nested"\n')
        self.publisher = registry_tests.publisher

    def prepare(self):
        private = self.fixture.root / "private"
        private.mkdir()
        with mock.patch.object(self.publisher.stager, "verify_bundle",
                               side_effect=self.fake_verify) as verified, \
                mock.patch.object(self.publisher.signer, "sign_and_verify") as signed, \
                mock.patch.object(self.publisher.uploader, "verify_published") as public:
            result = self.publisher.prepare(
                self.fixture.source, self.fixture.output,
                self.fixture.images_lock, private, local_transport=True)
        signed.assert_not_called()
        public.assert_not_called()
        return private, result, verified

    def fake_verify(self, blob, bundle):
        if bundle.read_bytes() != hashlib.sha256(blob.read_bytes()).hexdigest().encode():
            raise self.publisher.stager.StageError("MOCK publisher signature failed")

    def test_real_stager_verifies_all_three_mock_bundles_and_renders_public_descriptor(self):
        private, (reference, descriptor), verified = self.prepare()
        self.assertEqual(verified.call_count, 3)
        self.assertEqual(reference, "runtime/python@1.1.0")
        manifest = json.loads((private / "registry" / "manifest.json").read_bytes())
        self.assertEqual(manifest["image"], descriptor)
        files = private / "registry" / "files"
        expected = {entry["path"] for entry in manifest["files"]}
        expected.update(asset["name"] for asset in descriptor["assets"].values())
        self.assertEqual({path.relative_to(files).as_posix()
                          for path in files.rglob("*") if path.is_file()}, expected)
        self.assertNotIn("image-descriptor.json", expected)
        for entry in manifest["files"]:
            self.assertEqual(signing_tests.record((files / entry["path"]).read_bytes()),
                             {"sha256": entry["sha256"], "size": entry["size"]})
        for asset in descriptor["assets"].values():
            self.assertEqual(signing_tests.record((files / asset["name"]).read_bytes()),
                             {"sha256": asset["sha256"], "size": asset["size"]})
            self.assertEqual((files / asset["name"]).read_bytes(),
                             (private / "release" / asset["name"]).read_bytes())
        self.assertEqual(descriptor["release"], {
            "repository": "tinylabscom/mvm-packs", "tag": "pack-runtime-python-v1.1.0"})

    def test_wrong_source_bytes_fail_closed(self):
        with self.fixture.pack_source.open("a") as source:
            source.write("\n# changed reviewed source\n")
        with self.assertRaisesRegex(self.publisher.PublishError, "source bytes"):
            self.prepare()

    def test_wrong_lock_fail_closed(self):
        self.fixture.write_lock(manifest_sha256="d" * 64)
        with self.assertRaises(self.publisher.PublishError):
            self.prepare()

    def test_inconsistent_verifier_pin_in_mock_signed_evidence_fail_closed(self):
        composition_path = self.fixture.output / "composition.json"
        composition = json.loads(composition_path.read_bytes())
        composition["verifier_sha256"] = "d" * 64
        signing_tests.write_json(composition_path, composition)
        evidence_path = self.fixture.output / "image-evidence.json"
        evidence = json.loads(evidence_path.read_bytes())
        evidence["assets"]["composition.json"] = signing_tests.record(
            composition_path.read_bytes())
        signing_tests.write_json(evidence_path, evidence)
        self.fixture.fake_sign(evidence_path,
                               self.fixture.output / "image-evidence.sigstore.json")
        with self.assertRaises(self.publisher.PublishError):
            self.prepare()

    def test_unknown_inventory_fail_closed(self):
        (self.fixture.output / "unknown.json").write_text("{}")
        with self.assertRaisesRegex(self.publisher.PublishError, "missing or extra"):
            self.prepare()

    def test_changed_evidence_fail_closed(self):
        (self.fixture.output / "rootfs.ext4").write_bytes(b"changed")
        with self.assertRaisesRegex(self.publisher.PublishError, "digest differs"):
            self.prepare()

    def test_evidence_metadata_is_bounded_before_parsing_or_mock_verification(self):
        (self.fixture.output / "image-evidence.json").write_bytes(
            b"x" * (self.publisher.MAX_METADATA_BYTES + 1))
        with self.assertRaisesRegex(self.publisher.PublishError, "input snapshot refused"):
            self.prepare()

    def test_wrong_mock_signature_fail_closed(self):
        (self.fixture.output / "image-evidence.sigstore.json").write_bytes(b"wrong")
        with self.assertRaisesRegex(self.publisher.PublishError, "signature"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
