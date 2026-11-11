"""Application manifests describe bundles without publishing software fixtures."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder, validator
from application_manifest import manifest_bytes, validate_application, validate_source


def application():
    return {
        "schema_version": 1,
        "guest_arch": "aarch64",
        "bundle": {
            "source": "https://bundles.example/test/hello/1.0.0/app.mvmpkg",
            "archive_sha256": "a" * 64,
            "archive_size": 123,
            "key_id": "b" * 32,
        },
    }


class ApplicationManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "pack-sources" / "test" / "hello"
        self.source.mkdir(parents=True)
        self.packs = self.root / "packs"
        self.output = self.packs / "test" / "hello" / "1.0.0"
        self.write_source()
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def write_source(self, extra=""):
        self.source.joinpath("pack.toml").write_text(
            'version = "1.0.0"\ndescription = "Synthetic app descriptor"\n'
            + extra
            + '[application]\nschema_version = 1\nguest_arch = "aarch64"\n'
            '[application.bundle]\n'
            'source = "https://bundles.example/test/hello/1.0.0/app.mvmpkg"\n'
            f'archive_sha256 = "{"a" * 64}"\narchive_size = 123\n'
            f'key_id = "{"b" * 32}"\n'
        )

    def build(self):
        def fake_sign(_, bundle):
            bundle.write_text("synthetic test signature, not valid")

        with patch.object(builder, "PACKS", self.packs), \
                patch.object(builder, "verify_archive"), \
                patch.object(builder, "sign", side_effect=fake_sign) as sign:
            builder.build_one(self.source)
            return sign.call_count

    def validate(self, verify=False):
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.packs):
            validator.validate_manifest(self.output / "manifest.json", verify)
        return list(validator.problems)

    def test_build_validate_and_index_preserve_exact_descriptor(self):
        self.assertEqual(self.build(), 1)
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {"manifest.json", "manifest.sigstore.json"},
        )
        raw = (self.output / "manifest.json").read_bytes()
        self.assertEqual(raw, manifest_bytes(
            "test/hello@1.0.0", "Synthetic app descriptor", application()
        ))
        self.assertEqual(raw, Path(__file__).with_name("application_manifest_v2.json").read_bytes())
        self.assertEqual(json.loads(raw), {
            "schema_version": 2, "kind": "application",
            "reference": "test/hello@1.0.0",
            "description": "Synthetic app descriptor",
            "application": application(),
        })
        self.assertEqual(self.validate(), [])
        index = builder.registry_index(self.packs)
        self.assertEqual(index["schema_version"], 2)
        self.assertEqual(index["packs"][0]["versions"], [{
            "version": "1.0.0", "manifest_sha256": hashlib.sha256(raw).hexdigest()
        }])

    def test_existing_version_requires_verified_signature_and_identical_bytes(self):
        self.build()
        with patch.object(builder, "verify_bundle", return_value=True) as verify:
            self.assertEqual(self.build(), 0)
            self.assertEqual(verify.call_count, 1)
        with patch.object(builder, "verify_bundle", return_value=False):
            with self.assertRaisesRegex(SystemExit, "not trusted"):
                self.build()
        self.source.joinpath("pack.toml").write_text(
            self.source.joinpath("pack.toml").read_text().replace("archive_size = 123", "archive_size = 124")
        )
        with self.assertRaisesRegex(SystemExit, "bump the version"):
            self.build()

    def test_application_cannot_ship_source_or_published_payload(self):
        for name in ("pack", "extra"):
            with self.subTest(name=name):
                extra = self.source / name
                extra.mkdir()
                with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
                    self.build()
                extra.rmdir()
        self.build()
        extra = self.output / "files"
        extra.mkdir()
        self.assertTrue(any("payload" in error for error in self.validate()))
        with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
            self.build()

    def test_image_metadata_is_no_longer_supported(self):
        for extra in ("[image]\n", "[image_build]\n"):
            with self.subTest(extra=extra):
                self.write_source(extra)
                with self.assertRaisesRegex(SystemExit, "unknown pack metadata fields"):
                    builder.parse_pack_toml(self.source / "pack.toml")

    def test_application_version_rejects_build_metadata(self):
        path = self.source / "pack.toml"
        path.write_text(path.read_text().replace('"1.0.0"', '"1.0.0+build"'))
        with self.assertRaisesRegex(SystemExit, "canonical semver"):
            self.build()

    def test_strict_nested_fields_types_and_values(self):
        variants = []
        for key in application():
            value = application()
            del value[key]
            variants.append(value)
        value = application()
        value["files"] = []
        variants.append(value)
        for key in application()["bundle"]:
            value = application()
            del value["bundle"][key]
            variants.append(value)
        value = application()
        value["bundle"]["trust_key"] = "must not enroll keys"
        variants.append(value)
        for key, values in {
            "source": [None, {}, "", "http://example/app", "file:///tmp/app",
                       "https://user@example/app", "https://example/app?",
                       "https://example/app#", "https://example/../app",
                       "https://example\\evil/app", "https://example/\napp",
                       "oci://registry.example/test/app:latest"],
            "archive_sha256": ["A" * 64, "a" * 63, None, "a" * 64 + "\n"],
            "archive_size": [True, False, 0, -1, 1.2, "123", None, 2**64, 2 * 1024**3 + 1],
            "key_id": ["B" * 32, "b" * 31, None],
        }.items():
            for invalid in values:
                value = application()
                value["bundle"][key] = invalid
                variants.append(value)
        for key, invalid in (("schema_version", True), ("schema_version", 2),
                             ("guest_arch", "amd64"), ("guest_arch", None)):
            value = application()
            value[key] = invalid
            variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_application(value)

    def test_valid_architectures_and_digest_pinned_oci(self):
        for arch in ("aarch64", "x86_64"):
            value = application()
            value["guest_arch"] = arch
            value["bundle"]["source"] = "oci://registry.example/test/hello@sha256:" + "c" * 64
            validate_application(value)

    def test_shared_client_publisher_source_vectors(self):
        fixture = json.loads(Path(__file__).with_name("application_source_vectors.json").read_text())
        self.assertEqual(fixture["schema_version"], 1)
        for case in fixture["cases"]:
            with self.subTest(source=case["source"]):
                if case["valid"]:
                    validate_source(case["source"])
                else:
                    with self.assertRaises(ValueError):
                        validate_source(case["source"])

    def test_publisher_tracks_shared_application_validation_dependency(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github" / "workflows" / "publish.yml").read_text()
        push_paths = workflow.split("  push:\n", 1)[1].split("  schedule:\n", 1)[0]
        self.assertIn('      - "scripts/application_manifest.py"\n', push_paths)

    def test_validator_rejects_shape_drift_and_wrong_directory(self):
        self.build()
        path = self.output / "manifest.json"
        original = json.loads(path.read_bytes())
        mutations = [
            {"files": []}, {"image": {}}, {"kind": "policy"},
            {"schema_version": True}, {"schema_version": 3},
            {"reference": "test/other@1.0.0"}, {"reference": 3},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                value.update(mutation)
                path.write_text(json.dumps(value))
                self.assertTrue(self.validate())

    def test_application_signature_uses_existing_verifier(self):
        self.build()
        with patch.object(validator, "verify_signature") as verify:
            self.assertEqual(self.validate(verify=True), [])
            verify.assert_called_once_with(
                self.output / "manifest.json", "test/hello@1.0.0"
            )

    def test_duplicate_json_fields_are_rejected(self):
        self.build()
        path = self.output / "manifest.json"
        raw = path.read_text()
        path.write_text(raw.replace('"archive_size": 123', '"archive_size": 124, "archive_size": 123'))
        self.assertTrue(any("duplicate JSON" in error for error in self.validate()))

    def test_symlinks_and_unsigned_files_are_rejected(self):
        self.build()
        outside = self.root / "outside"
        outside.write_text("not part of descriptor")
        extra = self.output / "extra"
        extra.symlink_to(outside)
        self.assertTrue(any("symlink" in error for error in self.validate()))
        with self.assertRaisesRegex(SystemExit, "cannot contain payload"):
            self.build()
        extra.unlink()
        extra.write_text("not part of descriptor")
        self.assertTrue(any("payload" in error for error in self.validate()))

    def test_existing_policy_manifest_bytes_are_unchanged(self):
        root = Path(__file__).resolve().parent.parent
        for path in (root / "packs").glob("*/*/*/manifest.json"):
            manifest = json.loads(path.read_bytes())
            if manifest.get("kind") == "application":
                self.assertEqual(manifest["schema_version"], 2)
                continue
            namespace, suffix = manifest["reference"].split("/")
            name, _ = suffix.split("@")
            payload = path.parent / "files" / "pack"
            raw, _ = builder.manifest_bytes(
                manifest["reference"], manifest["description"], payload
            )
            with self.subTest(namespace=namespace, name=name):
                self.assertEqual(raw, path.read_bytes())

    def test_published_claude_policy_version_remains_byte_pinned(self):
        root = Path(__file__).resolve().parent.parent
        path = root / "packs" / "agent" / "claude" / "1.0.1" / "manifest.json"
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "c4be773ef57a0f4365730858e522207c5e609f9fda76f1499eab3d6b0c6293f5",
        )

    def test_claude_application_source_names_a_package_not_a_policy_payload(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "pack-sources" / "agent" / "claude"
        metadata = builder.parse_pack_toml(source / "pack.toml")
        self.assertEqual(metadata["version"], "2.0.1")
        self.assertEqual({path.name for path in source.iterdir()}, {"pack.toml"})
        pin = metadata["requirements"]["binaries"][0]
        self.assertEqual((pin["package"], pin["path"], pin["size"]),
                         ("claude-code-native", "bin/claude", 221263520))
        descriptor = metadata["application"]
        validate_application(descriptor)
        self.assertEqual(descriptor["guest_arch"], "aarch64")
        self.assertEqual(
            descriptor["bundle"]["source"],
            "https://github.com/tinylabscom/mvm-packs/releases/download/"
            "pack-agent-claude-v2.0.1/claude.mvmpkg",
        )

from tests.test_ed25519 import sign as ed25519_sign  # noqa: E402

TEST_SECRET = bytes(range(32))
TEST_PUBLIC = ed25519_sign(TEST_SECRET, b"")[0]
TEST_KEY_ID = hashlib.sha256(TEST_PUBLIC).hexdigest()[:32]


def make_mvmpkg(roles=("kernel", "rootfs"), key_id=TEST_KEY_ID, arch="aarch64", corrupt=None,
                extra_members=(), repeat_artifact=0, raw_manifest=None, signing_secret=TEST_SECRET,
                members=None):
    """Build a tiny synthetic .mvmpkg tar (manifest.json, manifest.sig, artifacts/)."""
    import io
    import tarfile
    files, artifacts = {}, []
    for role in roles:
        data = f"{role}-bytes".encode()
        files[f"artifacts/{role}"] = data
        artifacts.append({"name": role, "role": role, "path": f"artifacts/{role}",
                          "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    if corrupt:
        files[f"artifacts/{corrupt}"] = b"tampered"
    artifacts += [artifacts[0]] * repeat_artifact
    body = {"key_id": key_id, "arch": arch, "artifacts": artifacts}
    if members is not None:
        body["members"] = members
    manifest = raw_manifest or json.dumps(body).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        signature = ed25519_sign(signing_secret, manifest)[1]
        for name, data in {"manifest.json": manifest, "manifest.sig": signature, **files}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for info in extra_members:
            archive.addfile(info)
    return buffer.getvalue()


class ArchiveReadBackTests(unittest.TestCase):
    def descriptor(self, data, **bundle_changes):
        value = application()
        value["bundle"] |= {"archive_size": len(data), "key_id": TEST_KEY_ID,
                            "archive_sha256": hashlib.sha256(data).hexdigest()} | bundle_changes
        return value

    def check(self, descriptor, data, key=TEST_PUBLIC):
        import io

        def serve(url, timeout=None):
            if url.endswith("-bundle-publisher.pub"):
                if key is None:
                    raise OSError("404")
                return io.BytesIO(key)
            return io.BytesIO(data)

        with patch.object(builder.urllib.request, "urlopen", side_effect=serve):
            builder.verify_archive(descriptor)

    def test_archive_embedding_a_kernel_and_rootfs_passes(self):
        data = make_mvmpkg()
        self.check(self.descriptor(data), data)

    def test_wrong_digest_size_or_scheme_is_refused(self):
        data = make_mvmpkg()
        for descriptor in (
            self.descriptor(data, archive_sha256="0" * 64),
            self.descriptor(data, archive_size=len(data) - 1),
            self.descriptor(data, archive_size=len(data) + 1),
            self.descriptor(data, source="oci://registry.example/x@sha256:" + "a" * 64),
        ):
            with self.subTest(descriptor=descriptor["bundle"]), self.assertRaises(SystemExit):
                self.check(descriptor, data)

    def test_a_download_that_outlasts_the_deadline_is_refused(self):
        data = make_mvmpkg()
        clock = iter([0])  # the deadline is set at 0; every later reading is past it
        with patch.object(builder.time, "monotonic",
                          side_effect=lambda: next(clock, builder.DOWNLOAD_DEADLINE_SECONDS + 1)), \
                self.assertRaises(SystemExit):
            self.check(self.descriptor(data), data)

    def test_archive_without_the_application_is_refused(self):
        import tarfile
        symlink = tarfile.TarInfo("artifacts/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/etc/passwd"
        for label, data in {
            "no rootfs": make_mvmpkg(roles=("kernel",)),
            "no kernel": make_mvmpkg(roles=("rootfs",)),
            "wrong key id in manifest": make_mvmpkg(key_id="c" * 32),
            "signed by another key": make_mvmpkg(signing_secret=bytes(range(1, 33))),
            "wrong arch": make_mvmpkg(arch="x86_64"),
            "tampered artifact": make_mvmpkg(corrupt="rootfs"),
            "symlink member": make_mvmpkg(extra_members=(symlink,)),
            "artifact listed twice": make_mvmpkg(repeat_artifact=1),
            "deeply nested manifest": make_mvmpkg(raw_manifest=b"[" * 100000 + b"]" * 100000),
            "not a tar": b"x" * 100,
        }.items():
            with self.subTest(label), self.assertRaises(SystemExit):
                self.check(self.descriptor(data), data)

    def test_ambiguous_bundle_manifests_are_refused(self):
        def entry(name, role):
            data = f"{name}-bytes".encode()
            return {"name": name, "role": role, "path": f"artifacts/{name}",
                    "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        body = {"key_id": TEST_KEY_ID, "arch": "aarch64", "artifacts": [entry("kernel", "kernel"), entry("rootfs", "rootfs")]}
        two_rootfs = body | {"artifacts": body["artifacts"] + [entry("rootfs2", "rootfs")]}
        for label, data in {
            "duplicate JSON key": make_mvmpkg(raw_manifest=json.dumps(body)[:-1].encode() + b', "arch": "aarch64"}'),
            "two root filesystems": make_mvmpkg(roles=("kernel", "rootfs", "rootfs2"),
                                                raw_manifest=json.dumps(two_rootfs).encode()),
        }.items():
            with self.subTest(label), self.assertRaises(SystemExit):
                self.check(self.descriptor(data), data)
        valid = make_mvmpkg(raw_manifest=json.dumps(body).encode())
        self.check(self.descriptor(valid), valid)

    def test_bundle_key_must_exist_and_match_the_descriptor_key_id(self):
        data = make_mvmpkg()
        for label, key in {"missing key": None, "wrong key": bytes(range(1, 33)),
                           "short key": TEST_PUBLIC[:16]}.items():
            with self.subTest(label), self.assertRaises(SystemExit):
                self.check(self.descriptor(data), data, key=key)
        with self.assertRaises(SystemExit):
            builder.bundle_key_url("https://bundles.example/app.tar")

    POLICY = {"allow_hosts": ["api.anthropic.com:443"],
              "request_budget": {"max_requests": 1, "max_spend_microusd": 500000,
                                 "model": "claude-haiku-4-5-20251001"}}

    def check_policy(self, members, expected):
        import io
        data = make_mvmpkg(members=members)

        def serve(url, timeout=None):
            return io.BytesIO(TEST_PUBLIC if url.endswith("-bundle-publisher.pub") else data)

        with patch.object(builder.urllib.request, "urlopen", side_effect=serve):
            builder.verify_archive(self.descriptor(data), {"environment_policy": expected, "packages": [],
                                                           "commands": [], "binaries": []})

    def test_the_signed_environment_policy_must_equal_the_declared_one_exactly(self):
        env = lambda policy: [{"class": "environment", "policy": policy}]  # noqa: E731
        self.check_policy(env(self.POLICY), self.POLICY)          # exact: accepted, rootfs never read
        weak = {"allow_hosts": ["api.anthropic.com:443"]}
        extra = dict(self.POLICY, allow_hosts=["api.anthropic.com:443", "evil.example:443"])
        wider = dict(self.POLICY, request_budget=dict(self.POLICY["request_budget"], max_requests=2))
        for label, members in {
            "no request budget": env(weak),
            "an extra allowed host": env(extra),
            "a wider budget": env(wider),
            "no environment member": [],
            "two environment members": env(self.POLICY) + env(self.POLICY),
            "no policy at all": [{"class": "environment"}],
        }.items():
            with self.subTest(label), self.assertRaises(SystemExit):
                self.check_policy(members, self.POLICY)

    def test_declared_requirements_fail_closed_on_a_root_that_cannot_be_read(self):
        data = make_mvmpkg()   # its rootfs is not an ext4 image, so nothing can be confirmed
        import io

        def serve(url, timeout=None):
            return io.BytesIO(TEST_PUBLIC if url.endswith("-bundle-publisher.pub") else data)

        with patch.object(builder.urllib.request, "urlopen", side_effect=serve), \
                self.assertRaises(SystemExit):
            builder.verify_archive(self.descriptor(data), {"packages": ["bash"], "commands": []})

    def test_descriptions_cannot_carry_newlines_or_markdown_links(self):
        for description in ("line one\\nline two", "see [here](https://evil.example)", "tab\\there"):
            with self.subTest(description=description), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "pack.toml"
                path.write_text(f'version = "1.0.0"\ndescription = "{description}"\n')
                with self.assertRaises(SystemExit):
                    builder.parse_pack_toml(path)

    def test_requirements_are_only_allowed_on_application_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pack.toml"
            path.write_text('version = "1.0.0"\ndescription = "d"\n[requirements]\npackages = ["bash"]\n')
            with self.assertRaises(SystemExit):
                builder.parse_pack_toml(path)

    def test_a_digest_named_cache_saves_the_download_but_is_always_re_verified(self):
        import io
        import os
        data = make_mvmpkg()
        descriptor = self.descriptor(data)
        calls = []

        def serve(url, timeout=None):
            calls.append(url)
            return io.BytesIO(TEST_PUBLIC if url.endswith("-bundle-publisher.pub") else data)

        with tempfile.TemporaryDirectory() as cache, patch.dict(os.environ, {"MVM_ARCHIVE_CACHE": cache}), \
                patch.object(builder.urllib.request, "urlopen", side_effect=serve):
            builder.verify_archive(descriptor)
            archive_calls = [c for c in calls if not c.endswith("-bundle-publisher.pub")]
            self.assertEqual(len(archive_calls), 1)
            cached = Path(cache) / f"{descriptor['bundle']['archive_sha256']}.mvmpkg"
            self.assertTrue(cached.is_file())
            builder.verify_archive(descriptor)                      # reused: no second archive download
            self.assertEqual(len([c for c in calls if not c.endswith("-bundle-publisher.pub")]), 1)
            cached.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))   # a corrupted cache entry
            builder.verify_archive(descriptor)                      # deleted, downloaded again, still verified
            self.assertEqual(len([c for c in calls if not c.endswith("-bundle-publisher.pub")]), 2)
            self.assertEqual(cached.read_bytes(), data)

    def test_a_download_that_fails_verification_is_never_cached(self):
        import io
        import os
        data = make_mvmpkg()
        bad = self.descriptor(data, archive_sha256="0" * 64)

        def serve(url, timeout=None):
            return io.BytesIO(TEST_PUBLIC if url.endswith("-bundle-publisher.pub") else data)

        with tempfile.TemporaryDirectory() as cache, patch.dict(os.environ, {"MVM_ARCHIVE_CACHE": cache}), \
                patch.object(builder.urllib.request, "urlopen", side_effect=serve):
            with self.assertRaises(SystemExit):
                builder.verify_archive(bad)
            self.assertEqual(list(Path(cache).iterdir()), [])

    def test_unreadable_archive_is_refused_before_signing(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(builder.urllib.request, "urlopen", side_effect=OSError("404")), \
                patch.object(builder, "PACKS", Path(tmp) / "packs"), \
                patch.object(builder, "sign") as sign:
            source = Path(tmp) / "pack-sources" / "test" / "hello"
            source.mkdir(parents=True)
            source.joinpath("pack.toml").write_text(
                'version = "1.0.0"\ndescription = "d"\n[application]\nschema_version = 1\n'
                'guest_arch = "aarch64"\n[application.bundle]\n'
                'source = "https://bundles.example/a.mvmpkg"\n'
                f'archive_sha256 = "{"a" * 64}"\narchive_size = 123\nkey_id = "{"b" * 32}"\n')
            with self.assertRaises(SystemExit):
                builder.build_one(source)
            sign.assert_not_called()
