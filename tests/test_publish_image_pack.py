"""A built pack enters the registry only after verified release readback."""

import importlib.util
import hashlib
import json
import os
import subprocess
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
                role: {"name": name, "sha256": hashlib.sha256(b"x").hexdigest(), "size": 1}
                for role, name in publisher.builder.BUILT_IMAGE_ASSETS.items()
            },
        }

    def fake_stage(self, _evidence, _reference, _source, _lock, output):
        output.mkdir()
        (output / "image-descriptor.json").write_text(json.dumps(self.descriptor))
        for name in publisher.stager.RELEASE_NAMES:
            (output / name).write_bytes(b"x")

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
        self.assertEqual({path.relative_to(out / "files").as_posix()
                          for path in (out / "files").rglob("*") if path.is_file()},
                         {entry["path"] for entry in manifest["files"]})
        self.assertIn("1.1.0", json.dumps(json.loads(
            (self.packs.parent / "index.json").read_text())))
        self.assertFalse((self.packs / "index.json").exists())

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

    def test_prepare_never_signs_or_checks_public_release(self):
        private = self.root / "private"
        private.mkdir()
        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                mock.patch.object(publisher.signer, "sign_and_verify") as signed, \
                mock.patch.object(publisher.uploader, "verify_published") as uploaded:
            reference, descriptor = publisher.prepare(
                self.source, self.evidence, self.lock, private)
        signed.assert_not_called()
        uploaded.assert_not_called()
        self.assertEqual(reference, "runtime/python@1.1.0")
        self.assertEqual(descriptor, self.descriptor)
        self.assertEqual({p.name for p in private.iterdir()}, {"registry", "release"})
        self.assertFalse((private / "registry" / "manifest.sigstore.json").exists())

    def test_comparison_refuses_manifest_asset_and_inventory_drift(self):
        actual, candidate = self.root / "actual", self.root / "candidate"
        for directory in (actual, candidate):
            directory.mkdir()
            with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage):
                publisher.prepare(self.source, self.evidence, self.lock, directory,
                                  local_transport=directory == candidate)
        publisher.compare_candidate(actual, candidate)
        for relative in ["registry/manifest.json", "registry/files/pack/group.toml",
                         "release/image-descriptor.json"] + [
                             f"registry/files/{asset['name']}"
                             for asset in self.descriptor["assets"].values()]:
            path = candidate / relative
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.assertRaisesRegex(publisher.PublishError, "re-observation"):
                publisher.compare_candidate(actual, candidate)
            path.write_bytes(original)
        (candidate / "release" / "unknown").write_bytes(b"unknown")
        with self.assertRaisesRegex(publisher.PublishError, "inventory"):
            publisher.compare_candidate(actual, candidate)

    def comparison_pair(self):
        actual, candidate = self.root / "actual", self.root / "candidate"
        for directory in (actual, candidate):
            directory.mkdir()
            with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage):
                publisher.prepare(self.source, self.evidence, self.lock, directory,
                                  local_transport=directory == candidate)
        return actual, candidate

    def test_comparison_final_inventory_rejects_added_file_during_first_hash(self):
        actual, candidate = self.comparison_pair()
        original_record = publisher.stager.record
        changed = False

        def mutate_once(path):
            nonlocal changed
            if not changed:
                changed = True
                (candidate / "registry" / "files" / "undeclared").write_bytes(b"extra")
            return original_record(path)

        with mock.patch.object(publisher.stager, "record", side_effect=mutate_once):
            with self.assertRaisesRegex(publisher.PublishError, "inventory changed"):
                publisher.compare_candidate(actual, candidate)

    def test_comparison_final_identity_rejects_same_bytes_replacement(self):
        actual, candidate = self.comparison_pair()
        original_copy = publisher.binder.copy_regular
        changed = False

        def replace_after_snapshot(source, target, **kwargs):
            nonlocal changed
            original_copy(source, target, **kwargs)
            if not changed and source.is_relative_to(candidate):
                changed = True
                body = source.read_bytes()
                source.unlink()
                source.write_bytes(body)

        with mock.patch.object(publisher.binder, "copy_regular",
                               side_effect=replace_after_snapshot):
            with self.assertRaisesRegex(publisher.PublishError, "inventory changed"):
                publisher.compare_candidate(actual, candidate)

    def test_comparison_oversized_bundle_and_inventory_are_bounded(self):
        actual, candidate = self.comparison_pair()
        bundle = candidate / "registry" / "manifest.sigstore.json"
        bundle.write_bytes(b"x" * (publisher.MAX_METADATA_BYTES + 1))
        with self.assertRaisesRegex(publisher.PublishError, "snapshot bound"):
            publisher.compare_candidate(actual, candidate)
        bundle.unlink()
        for index in range(70):
            (candidate / "registry" / f"extra-{index}").write_bytes(b"x")
        with mock.patch.object(publisher, "MAX_PAYLOAD_FILES", 1):
            with self.assertRaisesRegex(publisher.PublishError, "entry bound"):
                publisher.compare_candidate(actual, candidate)

    def test_fifo_metadata_and_comparison_race_fail_closed_without_hanging(self):
        worker = r'''
import os
from unittest import mock
from tests.test_publish_image_pack import RegistryImageTests, publisher
fixture = RegistryImageTests()
fixture.setUp()
try:
    metadata = fixture.source / "pack.toml"
    metadata.unlink()
    if MODE == "oversized":
        metadata.write_bytes(b"x" * (publisher.MAX_METADATA_BYTES + 1))
    else:
        os.mkfifo(metadata)
    for public in (False, True):
        try:
            if public:
                publisher.publish(fixture.source, fixture.evidence, fixture.lock,
                                  fixture.environment, object())
            else:
                private = fixture.root / "private"
                private.mkdir()
                publisher.prepare(fixture.source, fixture.evidence, fixture.lock, private)
        except publisher.PublishError:
            pass
        else:
            raise AssertionError("unsafe source accepted")
finally:
    fixture.doCleanups()
'''
        for mode in ("fifo", "oversized"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, "-c", f"MODE = {mode!r}\n" + worker],
                    cwd=ROOT, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
        race = r'''
import os
from unittest import mock
from tests.test_publish_image_pack import RegistryImageTests, publisher
fixture = RegistryImageTests()
fixture.setUp()
try:
    actual, candidate = fixture.comparison_pair()
    original = publisher.binder.copy_regular
    changed = False
    def swap(source, target, **kwargs):
        global changed
        if not changed and source.is_relative_to(candidate):
            changed = True
            source.unlink()
            os.mkfifo(source)
        original(source, target, **kwargs)
    with mock.patch.object(publisher.binder, "copy_regular", side_effect=swap):
        try:
            publisher.compare_candidate(actual, candidate)
        except publisher.PublishError:
            pass
        else:
            raise AssertionError("FIFO race accepted")
finally:
    fixture.doCleanups()
'''
        result = subprocess.run([sys.executable, "-c", race], cwd=ROOT,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_output_ancestor_swap_leaves_redirect_target_untouched(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-private-") as temporary:
            root = Path(temporary)
            ancestor = root / "ancestor"
            ancestor.mkdir()
            redirect = root / "redirect"
            redirect.mkdir()
            (redirect / "sentinel").write_bytes(b"keep")
            original_prepare = publisher.prepare

            def swap_after_preparation(*args, **kwargs):
                result = original_prepare(*args, **kwargs)
                ancestor.rename(root / "captured-ancestor")
                ancestor.symlink_to(redirect, target_is_directory=True)
                return result

            with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                    mock.patch.object(publisher, "prepare", side_effect=swap_after_preparation):
                with self.assertRaisesRegex(publisher.PublishError, "ancestor"):
                    publisher.prepare_private(self.source, self.evidence, self.lock,
                                              ancestor / "candidate")
            self.assertEqual({path.name for path in redirect.iterdir()}, {"sentinel"})
            self.assertEqual((redirect / "sentinel").read_bytes(), b"keep")
            self.assertEqual(list((root / "captured-ancestor").iterdir()), [])

    def test_transport_collision_refuses_overwriting_source_payload(self):
        private = self.root / "private"
        private.mkdir()
        original_copy = publisher.copy_payload

        def colliding_copy(source, destination):
            original_copy(source, destination)
            (destination.parent / "rootfs.ext4").write_bytes(b"keep")

        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                mock.patch.object(publisher, "copy_payload", side_effect=colliding_copy):
            with self.assertRaisesRegex(publisher.PublishError, "collides"):
                publisher.prepare(self.source, self.evidence, self.lock, private,
                                  local_transport=True)
        self.assertEqual((private / "registry/files/rootfs.ext4").read_bytes(), b"keep")

    def test_transport_copy_refuses_changed_verified_asset_size(self):
        private = self.root / "private"
        private.mkdir()

        def changed_stage(*args):
            self.fake_stage(*args)
            (args[-1] / "rootfs.ext4").write_bytes(b"grown")

        with mock.patch.object(publisher.stager, "stage", side_effect=changed_stage):
            with self.assertRaisesRegex(publisher.PublishError, "transport copy failed"):
                publisher.prepare(self.source, self.evidence, self.lock, private,
                                  local_transport=True)

    def test_transport_copy_refuses_linked_verified_asset(self):
        private = self.root / "private"
        private.mkdir()

        def linked_stage(*args):
            self.fake_stage(*args)
            asset = args[-1] / "rootfs.ext4"
            asset.unlink()
            asset.symlink_to(self.lock)

        with mock.patch.object(publisher.stager, "stage", side_effect=linked_stage):
            with self.assertRaisesRegex(publisher.PublishError, "transport copy failed"):
                publisher.prepare(self.source, self.evidence, self.lock, private,
                                  local_transport=True)

    def test_image_transport_is_not_charged_to_source_payload_bound(self):
        private = self.root / "private"
        private.mkdir()
        image = b"x" * 1024
        self.descriptor["assets"]["rootfs"].update(
            sha256=hashlib.sha256(image).hexdigest(), size=len(image))

        def larger_stage(*args):
            self.fake_stage(*args)
            (args[-1] / "rootfs.ext4").write_bytes(image)

        with mock.patch.object(publisher.stager, "stage", side_effect=larger_stage), \
                mock.patch.object(publisher, "MAX_PAYLOAD_BYTES", 64):
            publisher.prepare(self.source, self.evidence, self.lock, private,
                              local_transport=True)
        self.assertEqual((private / "registry/files/rootfs.ext4").read_bytes(), image)

    def test_private_output_outside_workspace_refuses_before_evidence_check(self):
        with mock.patch.object(publisher.stager, "stage") as staged:
            with self.assertRaisesRegex(publisher.PublishError, "workspace"):
                publisher.prepare_private(self.source, self.evidence, self.lock,
                                          self.root / "output")
        staged.assert_not_called()

    def test_public_regeneration_drift_refuses_before_signing_after_public_check(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage):
            publisher.prepare(self.source, self.evidence, self.lock, candidate,
                              local_transport=True)
        (candidate / "registry" / "manifest.json").write_bytes(b"author JSON")
        with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                mock.patch.object(publisher.uploader, "verify_published") as public, \
                mock.patch.object(publisher.signer, "sign_and_verify") as signed, \
                mock.patch.object(publisher.builder, "PACKS", self.packs):
            with self.assertRaisesRegex(publisher.PublishError, "re-observation"):
                publisher.publish(self.source, self.evidence, self.lock,
                                  self.environment, object(), candidate)
        public.assert_called_once()
        signed.assert_not_called()
        self.assertFalse(self.packs.exists())

    def test_private_cli_writes_unsigned_layout_without_constructing_github_client(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-private-") as temporary:
            output = Path(temporary) / "candidate"
            with mock.patch.object(publisher.stager, "stage", side_effect=self.fake_stage), \
                    mock.patch.object(publisher.signer, "sign_and_verify") as signed, \
                    mock.patch.object(publisher.uploader, "GithubReleaseClient") as client:
                publisher.main([
                    "--pack-source", str(self.source), "--evidence", str(self.evidence),
                    "--mvm-images-lock", str(self.lock), "--private-output", str(output)])
            signed.assert_not_called()
            client.assert_not_called()
            self.assertTrue((output / "registry" / "manifest.json").is_file())
            self.assertFalse((output / "registry" / "manifest.sigstore.json").exists())

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
