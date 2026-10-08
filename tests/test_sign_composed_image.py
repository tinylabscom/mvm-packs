"""Signing must bind exact reproduced bytes and the publisher workflow identity."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sign-composed-image.py"
spec = importlib.util.spec_from_file_location("sign_composed_image", SCRIPT)
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


def record(body):
    return {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root / "candidate.json"
        self.composed = self.root / "composed"
        self.composed.mkdir()
        self.output = self.root / "signed"
        self.images_lock = self.root / "images.lock"
        self.base = {
            "repository": "tinylabscom/mvm-images",
            "release_tag": "image-set/v0.2.4",
            "manifest_sha256": "a" * 64,
        }
        self.write_lock()
        self.candidate_value = {
            "schema_version": 1,
            "kind": "unsigned-image-candidate",
            "platform": "linux/aarch64",
            "pack_source": record(b"pack"),
            "base_set": self.base,
            "signed_root_manifest": record(b"manifest"),
            "signed_root_bundle": record(b"bundle"),
            "verifier_sha256": "b" * 64,
            "verification_scope": "selected-base-artifacts-only",
            "base_artifacts": {"rootfs.ext4": record(b"base")},
            "application_layer": {"rootfs.ext4": record(b"app")},
        }
        write_json(self.candidate, self.candidate_value)
        self.assets = {
            "rootfs.ext4": b"rootfs-bytes",
            "rootfs.verity": b"verity-bytes",
            "rootfs.roothash": b"roothash-bytes",
        }
        report = {"assets": [
            {"path": name, **record(body)} for name, body in sorted(self.assets.items())
        ]}
        self.assets["asset-report.json"] = (
            json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        for name, body in self.assets.items():
            (self.composed / name).write_bytes(body)
        self.composition = {
            "schema_version": 1,
            "kind": "unsigned-composed-image",
            "base_set": self.base,
            "candidate_sha256": record(self.candidate.read_bytes())["sha256"],
            "application_layer_sha256": record(b"app")["sha256"],
            "verifier_sha256": "b" * 64,
            "assets": {name: record(body) for name, body in self.assets.items()},
        }
        write_json(self.composed / "composition.json", self.composition)
        self.environment = {
            "GITHUB_REPOSITORY": "tinylabscom/mvm-packs",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF":
                "tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "c" * 40,
        }

    def write_lock(self, release_tag=None, manifest_sha256=None):
        self.images_lock.write_text(
            'schema_version = 2\nrepository = "tinylabscom/mvm-images"\n'
            '[image_set]\nrepository = "tinylabscom/mvm-images"\n'
            f'release_tag = "{release_tag or self.base["release_tag"]}"\n'
            f'manifest_sha256 = "{manifest_sha256 or self.base["manifest_sha256"]}"\n'
        )

    def prepare(self):
        signer.prepare(self.composed, self.candidate, "runtime/python@1.1.0",
                       self.output, self.environment, self.images_lock)

    def fake_sign(self, path, bundle):
        bundle.write_bytes(hashlib.sha256(path.read_bytes()).hexdigest().encode())

    def test_signs_only_verified_bytes_and_binds_base_and_provenance(self):
        with mock.patch.object(signer, "sign_and_verify", side_effect=self.fake_sign) as called:
            self.prepare()
        self.assertEqual(called.call_count, 3)
        self.assertEqual((self.output / "rootfs.ext4").read_bytes(), b"rootfs-bytes")
        provenance = json.loads((self.output / "provenance.json").read_text())
        self.assertEqual(provenance["subject"][0]["digest"]["sha256"],
                         record(b"rootfs-bytes")["sha256"])
        parameters = provenance["predicate"]["buildDefinition"]["externalParameters"]
        self.assertEqual(parameters["base_set"], self.base)
        self.assertEqual(parameters["reference"], "runtime/python@1.1.0")
        dependencies = provenance["predicate"]["buildDefinition"]["resolvedDependencies"]
        self.assertIn({"uri": "mvm/images.lock", "digest": {
            "sha256": record(self.images_lock.read_bytes())["sha256"]}}, dependencies)
        descriptor = json.loads((self.output / "image-evidence.json").read_text())
        self.assertEqual(descriptor["base_set"], self.base)
        self.assertEqual(descriptor["assets"]["provenance.json"],
                         record((self.output / "provenance.json").read_bytes()))
        self.assertTrue((self.output / "image-evidence.sigstore.json").is_file())
        self.assertEqual((self.output / "candidate.json").read_bytes(), self.candidate.read_bytes())

    def test_tampered_image_or_candidate_refuses_before_signing(self):
        (self.composed / "rootfs.ext4").write_bytes(b"tampered")
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "digest"):
                self.prepare()
        called.assert_not_called()
        self.assertFalse(self.output.exists())
        (self.composed / "rootfs.ext4").write_bytes(b"rootfs-bytes")
        self.candidate.write_bytes(b"different")
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "candidate"):
                self.prepare()
        called.assert_not_called()

    def test_wrong_workflow_or_branch_refuses_before_signing(self):
        for key, value in (("GITHUB_REF", "refs/heads/topic"),
                           ("GITHUB_WORKFLOW_REF", "other/workflow@refs/heads/main"),
                           ("GITHUB_RUN_ID", "not-a-run"),
                           ("GITHUB_SHA", "not-a-commit")):
            with self.subTest(key=key):
                changed = dict(self.environment)
                changed[key] = value
                with mock.patch.object(signer, "sign_and_verify") as called:
                    with self.assertRaisesRegex(signer.SigningError, "publisher workflow"):
                        signer.prepare(self.composed, self.candidate,
                                       "runtime/python@1.1.0", self.output, changed,
                                       self.images_lock)
                called.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_failed_signature_verification_leaves_no_output(self):
        with mock.patch.object(signer, "sign_and_verify", side_effect=signer.SigningError("invalid signature")):
            with self.assertRaisesRegex(signer.SigningError, "invalid signature"):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_asset_report_and_extra_input_refuse_before_signing(self):
        (self.composed / "asset-report.json").write_bytes(b"{}")
        self.composition["assets"]["asset-report.json"] = record(b"{}")
        write_json(self.composed / "composition.json", self.composition)
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "asset report"):
                self.prepare()
        called.assert_not_called()
        (self.composed / "untracked").write_bytes(b"unexpected")
        with self.assertRaisesRegex(signer.SigningError, "extra files"):
            self.prepare()

    def test_symlinks_and_existing_destination_refuse(self):
        image = self.composed / "rootfs.ext4"
        image.unlink()
        image.symlink_to(self.candidate)
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaises(signer.SigningError):
                self.prepare()
        called.assert_not_called()
        self.assertFalse(self.output.exists())
        image.unlink()
        image.write_bytes(b"rootfs-bytes")
        self.output.mkdir()
        (self.output / "operator-data").write_bytes(b"keep")
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "new directory"):
                self.prepare()
        called.assert_not_called()
        self.assertEqual((self.output / "operator-data").read_bytes(), b"keep")

    def test_advanced_or_tampered_lock_refuses_before_signing(self):
        for release_tag, manifest_sha256 in (
            ("image-set/v0.2.5", None), (None, "0" * 64),
        ):
            with self.subTest(release_tag=release_tag, manifest_sha256=manifest_sha256):
                self.write_lock(release_tag, manifest_sha256)
                with mock.patch.object(signer, "sign_and_verify") as called:
                    with self.assertRaisesRegex(signer.SigningError, "current images.lock"):
                        self.prepare()
                called.assert_not_called()
                self.assertFalse(self.output.exists())
        self.images_lock.write_text('schema_version = 2\n[image_set]\n')
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "images.lock"):
                self.prepare()
        called.assert_not_called()

    def test_linked_lock_refuses_before_signing(self):
        linked = self.root / "linked.lock"
        linked.write_bytes(self.images_lock.read_bytes())
        self.images_lock.unlink()
        self.images_lock.symlink_to(linked)
        with mock.patch.object(signer, "sign_and_verify") as called:
            with self.assertRaisesRegex(signer.SigningError, "input snapshot"):
                self.prepare()
        called.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_key_signing_is_refused(self):
        path = self.root / "blob"
        path.write_bytes(b"content")
        with mock.patch.dict(signer.os.environ, {"COSIGN_KEY": "test-key"}):
            with mock.patch.object(signer.subprocess, "run") as run:
                with self.assertRaisesRegex(signer.SigningError, "key-based signing"):
                    signer.sign_and_verify(path, self.root / "bundle")
        run.assert_not_called()

    def test_cosign_verification_pins_exact_identity_and_issuer(self):
        path = self.root / "blob"
        bundle = self.root / "bundle"
        path.write_bytes(b"content")
        def execute(command, **_kwargs):
            if command[1] == "sign-blob":
                bundle.write_bytes(b"bundle")
        with mock.patch.object(signer.subprocess, "run", side_effect=execute) as run:
            signer.sign_and_verify(path, bundle)
        self.assertEqual(run.call_count, 2)
        verify = run.call_args_list[1].args[0]
        self.assertEqual(verify[0:2], ["cosign", "verify-blob"])
        self.assertIn(signer.PUBLISHER_IDENTITY, verify)
        self.assertIn(signer.PUBLISHER_ISSUER, verify)


if __name__ == "__main__":
    unittest.main()
