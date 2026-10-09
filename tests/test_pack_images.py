"""Publisher contract tests for signed image-bearing pack manifests."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-packs.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("build_packs", SCRIPT)
build_packs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_packs)


class PackImageTests(unittest.TestCase):
    def image_build(self):
        image = self.built_image()
        return {key: image[key] for key in (
            "schema_version", "platform", "base_set", "release"
        )} | {"schema_version": 1}

    def test_image_build_intent_needs_no_future_asset_digests(self):
        intent = self.image_build()
        build_packs.validate_image_build_intent(intent, "runtime/python@1.0.0")
        self.assertNotIn("assets", intent)
        for mutation in (
            lambda value: value["base_set"].update(manifest_sha256="0"),
            lambda value: value["base_set"].update(release_tag="image-set/v0.2.5+mutable"),
            lambda value: value["release"].update(tag="pack-runtime-python-v1.0.1"),
            lambda value: value.update(assets={}),
            lambda value: value.update(schema_version=True),
        ):
            changed = json.loads(json.dumps(intent))
            mutation(changed)
            with self.subTest(changed=changed), self.assertRaises(SystemExit):
                build_packs.validate_image_build_intent(changed, "runtime/python@1.0.0")

    def test_image_build_intent_cannot_be_published_before_signed_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pack-sources" / "runtime" / "python"
            (source / "pack").mkdir(parents=True)
            (source / "pack.toml").write_text(
                'version = "1.0.0"\ndescription = "Python"\n'
                '[image_build]\nschema_version = 1\nplatform = "linux/x86_64"\n'
                '[image_build.base_set]\nrepository = "tinylabscom/mvm-images"\n'
                'release_tag = "image-set/v0.2.4"\n'
                f'manifest_sha256 = "{"a" * 64}"\n'
                '[image_build.release]\nrepository = "tinylabscom/mvm-packs"\n'
                'tag = "pack-runtime-python-v1.0.0"\n'
            )
            (source / "pack" / "profile.toml").write_text("schema_version = 1\n")
            with patch.object(build_packs, "PACKS", root / "packs"), \
                    patch.object(build_packs, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "not publishable"):
                    build_packs.build_one(source)
            sign.assert_not_called()
            self.assertFalse((root / "packs").exists())

    def built_image(self):
        digest = "a" * 64
        names = {
            "rootfs": "rootfs.ext4",
            "verity": "rootfs.verity",
            "roothash": "rootfs.roothash",
            "mvm_meta": "mvm-meta.json",
            "rootfs_signature_bundle": "rootfs.signature.json",
            "provenance_statement": "provenance.json",
            "provenance_signature_bundle": "provenance.signature.json",
        }
        return {
            "schema_version": 2,
            "platform": "linux/x86_64",
            "base_set": {
                "repository": "tinylabscom/mvm-images",
                "release_tag": "image-set/v0.2.4",
                "manifest_sha256": digest,
            },
            "release": {
                "repository": "tinylabscom/mvm-packs",
                "tag": "pack-runtime-python-v1.0.0",
            },
            "assets": {
                role: {"name": name, "sha256": digest, "size": 1}
                for role, name in names.items()
            },
        }

    def test_built_descriptor_has_only_pinned_external_assets(self):
        build_packs.validate_built_image_descriptor(
            self.built_image(), "runtime/python@1.0.0"
        )

    def test_measured_built_descriptor_is_serialized_in_signed_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "pack"
            payload.mkdir()
            (payload / "group.toml").write_text('description = "Python"\n')
            image = self.built_image()
            encoded, files = build_packs.manifest_bytes(
                "runtime/python@1.0.0", "Python", payload, image,
            )
            manifest = json.loads(encoded)
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["image"], image)
            self.assertEqual(len(files), 1)

    def test_built_descriptor_refuses_missing_or_unpinned_attestation(self):
        for role in ("provenance_statement", "provenance_signature_bundle"):
            descriptor = self.built_image()
            del descriptor["assets"][role]
            with self.subTest(role=role), self.assertRaisesRegex(SystemExit, "assets"):
                build_packs.validate_built_image_descriptor(
                    descriptor, "runtime/python@1.0.0"
                )
        descriptor = self.built_image()
        descriptor["assets"]["provenance_statement"]["sha256"] = ""
        with self.assertRaisesRegex(SystemExit, "sha256"):
            build_packs.validate_built_image_descriptor(
                descriptor, "runtime/python@1.0.0"
            )

    def test_built_descriptor_refuses_url_traversal_and_unknown_fields(self):
        mutations = (
            lambda d: d["assets"]["rootfs"].update(name="../rootfs.ext4"),
            lambda d: d["assets"]["rootfs"].update(url="https://example.test/rootfs.ext4"),
            lambda d: d["assets"]["rootfs"].update(size=-1),
            lambda d: d.update(extra="unsigned"),
        )
        for mutate in mutations:
            descriptor = self.built_image()
            mutate(descriptor)
            with self.subTest(descriptor=descriptor), self.assertRaises(SystemExit):
                build_packs.validate_built_image_descriptor(
                    descriptor, "runtime/python@1.0.0"
                )

    def test_built_descriptor_refuses_wrong_release_or_base(self):
        mutations = (
            lambda d: d["release"].update(repository="other/packs"),
            lambda d: d["release"].update(tag="pack-runtime-python-v1.0.1"),
            lambda d: d["base_set"].update(repository="other/images"),
            lambda d: d["base_set"].update(release_tag="main"),
            lambda d: d["base_set"].update(manifest_sha256="0"),
        )
        for mutate in mutations:
            descriptor = self.built_image()
            mutate(descriptor)
            with self.subTest(descriptor=descriptor), self.assertRaises(SystemExit):
                build_packs.validate_built_image_descriptor(
                    descriptor, "runtime/python@1.0.0"
                )

    def test_valid_built_descriptor_still_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pack-sources" / "runtime" / "python"
            (source / "pack").mkdir(parents=True)
            image = self.built_image()
            lines = ['version = "1.0.0"', 'description = "Python"', '[image]']
            lines += [f'{key} = {json.dumps(image[key])}' for key in ("schema_version", "platform")]
            for table in ("base_set", "release"):
                lines.append(f"[image.{table}]")
                lines += [f'{key} = {json.dumps(value)}' for key, value in image[table].items()]
            for role, asset in image["assets"].items():
                lines.append(f"[image.assets.{role}]")
                lines += [f'{key} = {json.dumps(value)}' for key, value in asset.items()]
            (source / "pack.toml").write_text("\n".join(lines) + "\n")
            (source / "pack" / "profile.toml").write_text("schema_version = 1\n")
            with patch.object(build_packs, "PACKS", root / "packs"), \
                    patch.object(build_packs, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "not publishable"):
                    build_packs.build_one(source)
            sign.assert_not_called()
            self.assertFalse((root / "packs").exists())

    def test_source_image_cannot_be_published_without_built_artifact_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pack-sources" / "runtime" / "python"
            image_dir = source / "pack" / "image"
            image_dir.mkdir(parents=True)
            (source / "pack.toml").write_text(
                'version = "1.0.0"\ndescription = "Python"\n'
                '[image]\nmanifest = "pack/image/mvm.toml"\n'
            )
            (image_dir / "mvm.toml").write_text('flake = "."\n')
            (image_dir / "flake.nix").write_text("{}\n")
            (image_dir / "flake.lock").write_text("{}\n")
            with patch.object(build_packs, "PACKS", root / "packs"), \
                    patch.object(build_packs, "sign") as sign:
                with self.assertRaisesRegex(SystemExit, "built image digest"):
                    build_packs.build_one(source)
            sign.assert_not_called()
            self.assertFalse((root / "packs").exists())

    def test_image_descriptor_names_only_signed_neighbors(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary)
            image_dir = payload / "image"
            image_dir.mkdir()
            (image_dir / "mvm.toml").write_text('flake = "."\n')
            (image_dir / "flake.nix").write_text("{}\n")
            (image_dir / "flake.lock").write_text('{}\n')

            encoded, files = build_packs.manifest_bytes(
                "runtime/python@1.0.0",
                "Python image",
                payload,
                {"manifest": "pack/image/mvm.toml"},
            )
            manifest = json.loads(encoded)
            self.assertEqual(manifest["image"], {"manifest": "pack/image/mvm.toml"})
            self.assertEqual(len(files), 3)

            (image_dir / "mvm.toml").write_text('[network]\nallow_hosts = ["example.com"]\n')
            with self.assertRaisesRegex(SystemExit, "host authority"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )
            (image_dir / "mvm.toml").write_text('flake = "github:elsewhere/image"\n')
            with self.assertRaisesRegex(SystemExit, "local signed flake"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )

            (image_dir / "flake.lock").unlink()
            with self.assertRaisesRegex(SystemExit, "not signed"):
                build_packs.manifest_bytes(
                    "runtime/python@1.0.0",
                    "Python image",
                    payload,
                    {"manifest": "pack/image/mvm.toml"},
                )

    def test_image_descriptor_refuses_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            for path in ("../mvm.toml", "pack/../mvm.toml", "pack/image/other.toml"):
                with self.subTest(path=path), self.assertRaisesRegex(SystemExit, "unsafe"):
                    build_packs.manifest_bytes(
                        "runtime/python@1.0.0",
                        "Python image",
                        Path(temporary),
                        {"manifest": path},
                    )


if __name__ == "__main__":
    unittest.main()
