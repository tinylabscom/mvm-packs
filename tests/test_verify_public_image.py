"""Public image validation must authenticate release bytes and provenance."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "upload_image_public_verify", ROOT / "scripts" / "upload-image-release.py"
)
uploader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uploader)


def record(body):
    return {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}


class PublicRelease:
    def __init__(self, assets, sha):
        self.assets = assets
        self.sha = sha
        self.tag = "pack-runtime-python-v1.1.0"
        self.release = {
            "id": 42, "draft": False, "tag_name": self.tag,
            "target_commitish": sha, "name": "runtime/python@1.1.0",
            "assets": [
                {"name": name, "size": len(body),
                 "digest": "sha256:" + record(body)["sha256"]}
                for name, body in assets.items()
            ],
        }

    def download(self, _tag, directory):
        for name, body in self.assets.items():
            (directory / name).write_bytes(body)

    def get_release_by_tag(self, _tag):
        return self.release

    def get_release(self, _release_id):
        return self.release

    def get_tag(self, _tag):
        return {"object": {"type": "commit", "sha": self.sha,
                           "url": "https://api.github.com/commit"}}


class PublicImageTests(unittest.TestCase):
    def setUp(self):
        self.reference = "runtime/python@1.1.0"
        self.sha = "e" * 40
        self.base = {
            "repository": "tinylabscom/mvm-images",
            "release_tag": "image-set/v0.2.4",
            "manifest_sha256": "a" * 64,
        }
        self.bodies = {
            "rootfs.ext4": b"rootfs", "rootfs.verity": b"verity",
            "rootfs.roothash": b"hash", "rootfs.signature.json": b"root signature",
            "provenance.signature.json": b"provenance signature",
        }
        self.bodies["mvm-meta.json"] = json.dumps({
            "name": "runtime-python", "accessible": False, "sealed": True,
            "entrypointKind": "command", "entrypointArgv": ["/app/entrypoint"],
            "initSystem": "busybox", "expectedBootMs": 300,
            "agentBinary": "real", "rootlessEntrypoint": True,
            "hypervisor": "firecracker", "overlayAware": True,
            "runtimeLean": True, "protocolVersion": 2, "libc": "musl",
        }).encode()
        composition = {
            "base_set": self.base, "candidate_sha256": "b" * 64,
            "application_layer_sha256": "c" * 64,
            "verifier_sha256": "d" * 64,
        }
        statement = uploader.signer.provenance(
            self.reference, composition, record(self.bodies["rootfs.ext4"]),
            "https://github.com/tinylabscom/mvm-packs/actions/runs/1234/attempts/1",
            self.sha, "f" * 64,
        )
        self.bodies["provenance.json"] = json.dumps(statement).encode()
        self.descriptor = {
            "schema_version": 2, "platform": "linux/x86_64",
            "base_set": self.base,
            "release": {"repository": "tinylabscom/mvm-packs",
                        "tag": "pack-runtime-python-v1.1.0"},
            "assets": {
                role: {"name": name, **record(self.bodies[name])}
                for role, name in uploader.helper(
                    "build-packs.py", "build_pack_public_test"
                ).BUILT_IMAGE_ASSETS.items()
            },
        }
        self.bodies["image-descriptor.json"] = json.dumps(self.descriptor).encode()
        self.client = PublicRelease(self.bodies, self.sha)

    def verify(self):
        with mock.patch.object(uploader.stager, "verify_bundle") as signatures:
            result = uploader.verify_public_image(
                self.descriptor, self.reference, self.client,
            )
        return result, signatures

    def test_valid_public_release_checks_both_signatures(self):
        source_sha, signatures = self.verify()
        self.assertEqual(source_sha, self.sha)
        self.assertEqual(signatures.call_count, 2)

    def test_changed_rootfs_or_descriptor_refuses(self):
        for name in ("rootfs.ext4", "image-descriptor.json"):
            original = self.client.assets[name]
            self.client.assets[name] = b"changed"
            with self.subTest(name=name), self.assertRaises(uploader.UploadError):
                self.verify()
            self.client.assets[name] = original

    def test_wrong_tag_or_draft_refuses(self):
        self.client.sha = "0" * 40
        with self.assertRaisesRegex(uploader.UploadError, "attested source"):
            self.verify()
        self.client.sha = self.sha
        self.client.release["draft"] = True
        with self.assertRaisesRegex(uploader.UploadError, "release identity"):
            self.verify()

    def test_signature_failure_refuses(self):
        with mock.patch.object(uploader.stager, "verify_bundle",
                               side_effect=uploader.stager.StageError("bad signature")):
            with self.assertRaisesRegex(uploader.UploadError, "bad signature"):
                uploader.verify_public_image(self.descriptor, self.reference,
                                             self.client)

    def test_provenance_refuses_wrong_base_or_missing_verifier(self):
        statement = json.loads(self.bodies["provenance.json"])
        dependencies = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
        for item in dependencies:
            if item["uri"] == "image-set.json":
                item["digest"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(uploader.UploadError, "dependencies"):
            uploader.verify_provenance(statement, self.descriptor, self.reference)
        statement = json.loads(self.bodies["provenance.json"])
        del statement["predicate"]["buildDefinition"]["internalParameters"]
        with self.assertRaisesRegex(uploader.UploadError, "does not bind"):
            uploader.verify_provenance(statement, self.descriptor, self.reference)


if __name__ == "__main__":
    unittest.main()
