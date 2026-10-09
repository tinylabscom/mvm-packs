"""An image release stays draft until every downloaded asset is verified."""

import importlib.util
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "upload-image-release.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("upload_image_release", SCRIPT)
uploader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uploader)


class FakeClient:
    def __init__(self, assets):
        self.assets = assets
        self.calls = []
        self.tag = None
        self.release = None
        self.download_tamper = None

    def get_tag(self, _tag):
        self.calls.append("get_tag")
        return self.tag

    def get_release_by_tag(self, _tag):
        self.calls.append("get_release_by_tag")
        return self.release

    def create_draft(self, tag, sha, reference):
        self.calls.append("create_draft")
        self.tag = {"ref": f"refs/tags/{tag}", "object": {
            "type": "commit", "sha": sha,
            "url": f"https://api.github.com/repos/tinylabscom/mvm-packs/git/commits/{sha}",
        }}
        self.release = {
            "id": 42, "draft": True, "tag_name": tag,
            "target_commitish": sha, "assets": [], "name": reference,
        }
        return dict(self.release)

    def upload(self, _tag, _assets):
        self.calls.append("upload")
        self.release["assets"] = [
            {"name": name, "size": len(body)} for name, body in self.assets.items()
        ]

    def get_release(self, _release_id):
        self.calls.append("get_release")
        return dict(self.release)

    def download(self, _tag, directory):
        self.calls.append("download")
        for name, body in self.assets.items():
            (directory / name).write_bytes(
                b"tampered" if name == self.download_tamper else body
            )

    def publish(self, _release_id):
        self.calls.append("publish")
        self.release["draft"] = False


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.staged = self.root / "staged"
        self.staged.mkdir()
        self.assets = {name: name.encode() for name in uploader.RELEASE_NAMES}
        self.assets["image-descriptor.json"] = b"descriptor"
        for name, body in self.assets.items():
            (self.staged / name).write_bytes(body)
        self.descriptor = {
            "release": {
                "repository": "tinylabscom/mvm-packs",
                "tag": "pack-runtime-python-v1.1.0",
            },
        }
        self.environment = {
            "GITHUB_REPOSITORY": "tinylabscom/mvm-packs",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": (
                "tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
            ),
            "GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
        }
        self.client = FakeClient(self.assets)

    def publish(self):
        uploader.publish_verified(
            self.staged, self.descriptor, "runtime/python@1.1.0",
            self.environment, self.client,
        )

    def test_publishes_only_after_download_and_tag_verification(self):
        self.publish()
        self.assertFalse(self.client.release["draft"])
        self.assertLess(self.client.calls.index("download"),
                        self.client.calls.index("publish"))
        self.assertEqual(self.client.calls.count("get_tag"), 3)

    def test_existing_tag_or_release_refuses_without_mutation(self):
        self.client.tag = {"object": {"type": "commit", "sha": "b" * 40}}
        with self.assertRaisesRegex(uploader.UploadError, "already exists"):
            self.publish()
        self.assertNotIn("create_draft", self.client.calls)
        self.client.tag = None
        self.client.calls.clear()
        self.client.release = {"id": 10}
        with self.assertRaisesRegex(uploader.UploadError, "already exists"):
            self.publish()
        self.assertNotIn("create_draft", self.client.calls)

    def test_tampered_download_leaves_draft(self):
        self.client.download_tamper = "rootfs.ext4"
        with self.assertRaisesRegex(uploader.UploadError, "downloaded asset"):
            self.publish()
        self.assertTrue(self.client.release["draft"])
        self.assertNotIn("publish", self.client.calls)

    def test_wrong_branch_refuses_before_remote_calls(self):
        self.environment["GITHUB_REF"] = "refs/heads/topic"
        with self.assertRaisesRegex(uploader.UploadError, "publisher workflow"):
            self.publish()
        self.assertEqual(self.client.calls, [])

    def test_linked_or_extra_staged_asset_refuses_before_remote_calls(self):
        image = self.staged / "rootfs.ext4"
        image.unlink()
        image.symlink_to(self.staged / "rootfs.verity")
        with self.assertRaisesRegex(uploader.UploadError, "linked or extra"):
            self.publish()
        self.assertEqual(self.client.calls, [])
        image.unlink()
        image.write_bytes(b"rootfs.ext4")
        (self.staged / "unsigned").write_bytes(b"data")
        with self.assertRaisesRegex(uploader.UploadError, "linked or extra"):
            self.publish()
        self.assertEqual(self.client.calls, [])

    def test_changed_tag_before_publication_leaves_draft(self):
        original_get_tag = self.client.get_tag
        def changed_tag(tag):
            value = original_get_tag(tag)
            if self.client.calls.count("get_tag") == 2:
                return {"object": {"type": "commit", "sha": "b" * 40}}
            return value
        self.client.get_tag = changed_tag
        with self.assertRaisesRegex(uploader.UploadError, "tag does not point"):
            self.publish()
        self.assertTrue(self.client.release["draft"])
        self.assertNotIn("publish", self.client.calls)

    def test_asset_metadata_drift_leaves_draft(self):
        original_get_release = self.client.get_release
        def changed_release(release_id):
            value = original_get_release(release_id)
            value["assets"][0] = dict(value["assets"][0], digest="sha256:" + "0" * 64)
            return value
        self.client.get_release = changed_release
        with self.assertRaisesRegex(uploader.UploadError, "asset digest"):
            self.publish()
        self.assertTrue(self.client.release["draft"])
        self.assertNotIn("publish", self.client.calls)

    def test_published_readback_refuses_changed_asset_metadata(self):
        original_get_release = self.client.get_release
        def changed_after_publish(release_id):
            value = original_get_release(release_id)
            if value["draft"] is False:
                value["assets"][0] = dict(value["assets"][0], size=0)
            return value
        self.client.get_release = changed_after_publish
        with self.assertRaisesRegex(uploader.UploadError, "asset metadata"):
            self.publish()
        self.assertIn("publish", self.client.calls)

    def test_api_distinguishes_absent_tag_from_authorization_failure(self):
        client = uploader.GithubReleaseClient("private-test-token")
        missing = urllib.error.HTTPError("https://api.github.com", 404,
                                         "not found", {}, None)
        forbidden = urllib.error.HTTPError("https://api.github.com", 403,
                                           "forbidden", {}, None)
        self.addCleanup(missing.close)
        self.addCleanup(forbidden.close)
        with mock.patch.object(uploader.urllib.request, "urlopen", side_effect=missing):
            self.assertIsNone(client.get_tag("pack-runtime-python-v1.1.0"))
        with mock.patch.object(uploader.urllib.request, "urlopen", side_effect=forbidden):
            with self.assertRaisesRegex(uploader.UploadError, "HTTP 403") as failure:
                client.get_tag("pack-runtime-python-v1.1.0")
        self.assertNotIn("private-test-token", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
