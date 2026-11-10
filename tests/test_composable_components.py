"""Candidate schema-4 runtime/tool descriptors are validated but never published."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder, validator
from application_manifest import composable_component_manifest_bytes, validate_composable_component


PIN = {"reference": "tool/helper@1.2.3", "manifest_sha256": "b" * 64}
FILES = [{"path": "pack/group.toml", "sha256": hashlib.sha256(b"policy").hexdigest(), "size": 6}]


def component():
    return {
        "schema_version": 1,
        "guest_arch": "aarch64",
        "requirements": {
            "filesystem_abi": 1, "libc": "musl", "loader": "/lib/ld-musl-aarch64.so.1",
            "minimum_kernel": "6.1.0", "required_capabilities": ["pty"],
        },
        "dependencies": [dict(PIN)],
        "archive": {
            "source": "https://example.com/component.tar",
            "archive_sha256": "a" * 64, "archive_size": 123,
        },
    }


class ComposableComponentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def publish_synthetic(self, kind, mutate=None):
        namespace = kind.removesuffix("_component")
        output = self.root / "packs" / namespace / "demo" / "1.0.0"
        (output / "files" / "pack").mkdir(parents=True, exist_ok=True)
        (output / "files" / "pack" / "group.toml").write_bytes(b"policy")
        (output / "manifest.sigstore.json").write_bytes(b"synthetic, not a signature")
        raw = composable_component_manifest_bytes(
            f"{namespace}/demo@1.0.0", "demo", kind, component(), FILES)
        body = json.loads(raw)
        if mutate:
            mutate(body)
            raw = json.dumps(body).encode()
        (output / "manifest.json").write_bytes(raw)
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.root / "packs"):
            validator.validate_manifest(output / "manifest.json")
        return raw, list(validator.problems)

    def test_runtime_and_tool_manifests(self):
        for kind in ("runtime_component", "tool_component"):
            with self.subTest(kind=kind):
                raw, errors = self.publish_synthetic(kind)
                self.assertEqual(errors, [])
                self.assertIn(b'"schema_version": 4', raw)
                self.assertNotIn(b"key_id", raw)
                self.assertNotIn(b"entrypoints", raw)
                self.assertNotIn(b"rootfs", raw)
                static = component()
                static["requirements"] = {
                    "filesystem_abi": 1, "libc": "static", "minimum_kernel": "6.1.0",
                    "required_capabilities": [],
                }
                static["dependencies"] = []
                validate_composable_component(static, kind)
                ordered = component()
                ordered["dependencies"].append({
                    "reference": "runtime/python@2.0.0", "manifest_sha256": "c" * 64,
                })
                ordered["archive"]["source"] = (
                    "oci://registry.example.com/runtime/python@sha256:" + "d" * 64)
                rendered = json.loads(composable_component_manifest_bytes(
                    kind.removesuffix("_component") + "/demo@1.0.0",
                    "demo", kind, ordered, FILES))
                self.assertEqual(rendered[kind]["dependencies"], ordered["dependencies"])

    def test_invalid_nested_fields(self):
        mutations = (
            lambda c: c.update(schema_version=True),
            lambda c: c.update(guest_arch=[]),
            lambda c: c.update(entrypoints=[]),
            lambda c: c["archive"].update(key_id="a" * 32),
            lambda c: c["archive"].update(source="file:///archive.tar"),
            lambda c: c["archive"].update(archive_sha256="A" * 64),
            lambda c: c["archive"].update(archive_size=True),
            lambda c: c["archive"].update(archive_size=2 * 1024**3 + 1),
            lambda c: c["requirements"].update(filesystem_abi=True),
            lambda c: c["requirements"].update(libc="static"),
            lambda c: c["requirements"].update(loader="/lib/../ld.so"),
            lambda c: c["requirements"].update(minimum_kernel="6.1"),
            lambda c: c["requirements"].update(required_capabilities=["pty", "pty"]),
            lambda c: c["requirements"].update(required_capabilities=["network.grant"]),
            lambda c: c.update(dependencies="tool/helper@1.2.3"),
            lambda c: c.update(dependencies=[dict(PIN)] * 17),
            lambda c: c["dependencies"].append(dict(PIN, reference="tool/helper@1.2.4")),
            lambda c: c["dependencies"].append(dict(PIN, reference="agent/claude@2.0.0")),
            lambda c: c["dependencies"][0].update(manifest_sha256="B" * 64),
            lambda c: c["dependencies"][0].update(extra=1),
        )
        for kind in ("runtime_component", "tool_component"):
            reference = kind.removesuffix("_component") + "/demo@1.0.0"
            self_pin = lambda c: c["dependencies"].append(
                dict(PIN, reference=kind.removesuffix("_component") + "/demo@0.9.0"))
            for mutate in (*mutations, self_pin):
                value = copy.deepcopy(component())
                mutate(value)
                with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                    validate_composable_component(value, kind, reference)

    def test_closed_manifest_and_policy_files(self):
        for mutate in (
            lambda m: m.update(kind="runtime_layer"),
            lambda m: m.update(schema_version=3),
            lambda m: m.update(reference="tool/demo@1.0.0"),
            lambda m: m.update(reference="runtime/demo@1.0.0+build"),
            lambda m: m.update(files=[]),
            lambda m: m.update(files=[dict(FILES[0], path="pack/install.sh")]),
            lambda m: m.update(files=[dict(FILES[0], size=0)]),
            lambda m: m.update(bundle={}),
            lambda m: m["runtime_component"].update(kernel={}),
        ):
            with self.subTest(mutate=mutate):
                _, errors = self.publish_synthetic("runtime_component", mutate)
                self.assertTrue(errors)
        _, errors = self.publish_synthetic("runtime_component")
        self.assertEqual(errors, [])
        manifest = self.root / "packs/runtime/demo/1.0.0/manifest.json"
        manifest.write_text(manifest.read_text().replace(
            '"archive_size": 123', '"archive_size": 124, "archive_size": 123'))
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.root / "packs"):
            validator.validate_manifest(manifest)
        self.assertTrue(any("duplicate JSON" in error for error in validator.problems))
        (self.root / "packs/runtime/demo/1.0.0/files/pack/install.sh").write_bytes(b"unsigned")
        _, errors = self.publish_synthetic("runtime_component")
        self.assertTrue(any("payload" in error for error in errors))

    def test_source_parser_and_publication_gate(self):
        for kind in ("runtime_component", "tool_component"):
            namespace = kind.removesuffix("_component")
            source = self.root / "pack-sources" / namespace / "demo"
            source.mkdir(parents=True, exist_ok=True)
            data = component()
            lines = (
                'version = "1.0.0"\ndescription = "demo"\n'
                f'[{kind}]\nschema_version = 1\nguest_arch = "aarch64"\n'
                f'dependencies = [{{reference = "tool/helper@1.2.3", manifest_sha256 = "{"b" * 64}"}}]\n'
                f'[{kind}.archive]\nsource = "https://example.com/component.tar"\n'
                f'archive_sha256 = "{"a" * 64}"\narchive_size = 123\n'
                f'[{kind}.requirements]\nfilesystem_abi = 1\nlibc = "musl"\n'
                'loader = "/lib/ld-musl-aarch64.so.1"\nminimum_kernel = "6.1.0"\n'
                'required_capabilities = ["pty"]\n'
            )
            path = source / "pack.toml"
            path.write_text(lines)
            self.assertEqual(builder.parse_pack_toml(path)[kind], data)
            for check_only in (True, False):
                with self.subTest(kind=kind, check_only=check_only), patch.object(builder, "sign") as sign:
                    with self.assertRaisesRegex(SystemExit, "not publishable"):
                        builder.build_one(source, check_only=check_only)
                    sign.assert_not_called()
            for invalid in (
                lines.replace('libc = "musl"', 'libc = "unknown"'),
                lines + '[application]\nschema_version = 1\n',
                lines.replace('version = "1.0.0"', 'version = "1.0.0+build"'),
            ):
                path.write_text(invalid)
                with self.assertRaises(SystemExit):
                    builder.parse_pack_toml(path)
            path.write_text(lines)


if __name__ == "__main__":
    unittest.main()
