"""Candidate application-only descriptor: no bundle signer or boot payload."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder, validator
from application_manifest import (
    application_component_manifest_bytes, validate_application_component,
)


def component():
    return {
        "schema_version": 1,
        "guest_arch": "aarch64",
        "archive": {
            "source": "https://example.com/app.tar",
            "archive_sha256": "a" * 64,
            "archive_size": 123,
        },
        "requirements": {
            "filesystem_abi": 1,
            "libc": "musl",
            "loader": "/lib/ld-musl-aarch64.so.1",
            "minimum_kernel": "6.1.0",
            "required_capabilities": ["pty"],
        },
        "entrypoints": [{"name": "default", "argv": ["/usr/bin/python3", "/srv/app/main.py"]}],
    }


class ApplicationComponentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "pack-sources" / "agent" / "demo"
        self.source.mkdir(parents=True)
        self.output = self.root / "packs" / "agent" / "demo" / "3.0.0"
        self.output.mkdir(parents=True)
        self.files = [{"path": "pack/group.toml", "sha256": hashlib.sha256(b"policy").hexdigest(),
                       "size": 6}]
        (self.output / "files" / "pack").mkdir(parents=True)
        (self.output / "files" / "pack" / "group.toml").write_bytes(b"policy")
        (self.output / "manifest.sigstore.json").write_bytes(b"synthetic, not a signature")
        validator.problems.clear()
        self.addCleanup(validator.problems.clear)

    def write_manifest(self, value=None):
        body = json.loads(application_component_manifest_bytes(
            "agent/demo@3.0.0", "demo", component(), self.files
        ))
        if value is not None:
            value(body)
        (self.output / "manifest.json").write_text(json.dumps(body))

    def validate(self):
        validator.problems.clear()
        with patch.object(validator, "ROOT", self.root), \
                patch.object(validator, "PACKS", self.root / "packs"):
            validator.validate_manifest(self.output / "manifest.json")
        return list(validator.problems)

    def test_descriptor_bytes_and_registry_validation(self):
        raw = application_component_manifest_bytes(
            "agent/demo@3.0.0", "demo", component(), self.files
        )
        self.assertEqual(json.loads(raw)["kind"], "application_component")
        self.assertNotIn(b"key_id", raw)
        self.assertNotIn(b"rootfs", raw)
        (self.output / "manifest.json").write_bytes(raw)
        self.assertEqual(self.validate(), [])

    def test_strict_component_fields(self):
        mutations = [
            lambda c: c.update(schema_version=True),
            lambda c: c.update(guest_arch=[]),
            lambda c: c.update(kernel={}),
            lambda c: c["archive"].update(key_id="b" * 32),
            lambda c: c["archive"].update(archive_sha256="A" * 64),
            lambda c: c["archive"].update(archive_size=True),
            lambda c: c["archive"].update(archive_size=2 * 1024**3 + 1),
            lambda c: c["archive"].update(source="file:///tmp/app"),
            lambda c: c["requirements"].update(filesystem_abi=True),
            lambda c: c["requirements"].update(libc="unknown"),
            lambda c: c["requirements"].update(libc="static"),
            lambda c: c["requirements"].update(loader="/lib/../loader"),
            lambda c: c["requirements"].update(minimum_kernel="6.1"),
            lambda c: c["requirements"].update(required_capabilities=["pty", "pty"]),
            lambda c: c["requirements"].update(required_capabilities=["network.grant"]),
            lambda c: c["entrypoints"].append({"name": "default", "argv": ["/bin/other"]}),
            lambda c: c["entrypoints"][0].update(argv=["sh", "-c", "echo unsafe"]),
            lambda c: c["entrypoints"][0].update(argv=["/bin/../sh"]),
            lambda c: c["entrypoints"][0].update(argv=["/bin/sh", "bad\x00arg"]),
            lambda c: c["entrypoints"][0].update(working_dir="/srv/app"),
        ]
        for mutate in mutations:
            value = copy.deepcopy(component())
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_application_component(value)
        static = component()
        static["requirements"].update(libc="static")
        del static["requirements"]["loader"]
        static["entrypoints"] = []
        validate_application_component(static)

    def test_closed_manifest_and_policy_inventory(self):
        for mutate in (
            lambda m: m.update(kind="application"),
            lambda m: m.update(files=[]),
            lambda m: m.update(files=[dict(self.files[0], path="artifacts/rootfs")]),
            lambda m: m.update(files=[dict(self.files[0], path="../../outside")]),
            lambda m: m.update(files=[dict(self.files[0], sha256=7)]),
            lambda m: m.update(files=[dict(self.files[0], size=True)]),
            lambda m: m.update(image={}),
            lambda m: m.update(reference="agent/demo@3.0.0+build"),
            lambda m: m["application_component"].update(bundle={}),
        ):
            self.write_manifest(mutate)
            with self.subTest(mutate=mutate):
                self.assertTrue(self.validate())
        self.write_manifest()
        path = self.output / "manifest.json"
        path.write_text(path.read_text().replace('"archive_size": 123',
                                                  '"archive_size": 124, "archive_size": 123'))
        self.assertTrue(any("duplicate JSON" in problem for problem in self.validate()))
        self.write_manifest()
        (self.output / "artifacts").mkdir()
        (self.output / "artifacts" / "kernel").write_bytes(b"not allowed")
        self.assertTrue(any("payload" in problem for problem in self.validate()))

    def test_renderer_requires_exact_identity_and_policy(self):
        for reference, files in (
            ("agent/demo@3.0.0+build", self.files),
            ("agent/demo@3.0.0", []),
            ("agent/demo@3.0.0", [dict(self.files[0], path="pack/init")]),
        ):
            with self.subTest(reference=reference, files=files), self.assertRaises(ValueError):
                application_component_manifest_bytes(reference, "demo", component(), files)

    def test_source_parses_but_cannot_be_signed_or_published(self):
        body = (f'version = "3.0.0"\ndescription = "demo"\n'
                f'[application_component]\nschema_version = 1\nguest_arch = "aarch64"\n'
                f'[[application_component.entrypoints]]\nname = "default"\nargv = ["/bin/demo"]\n'
                f'[application_component.archive]\nsource = "https://example.com/app.tar"\n'
                f'archive_sha256 = "{"a" * 64}"\narchive_size = 123\n'
                f'[application_component.requirements]\nfilesystem_abi = 1\nlibc = "musl"\n'
                f'loader = "/lib/ld-musl-aarch64.so.1"\n'
                f'minimum_kernel = "6.1.0"\nrequired_capabilities = []\n')
        (self.source / "pack.toml").write_text(body)
        self.assertEqual(builder.parse_pack_toml(self.source / "pack.toml")["application_component"]["schema_version"], 1)
        with self.assertRaisesRegex(SystemExit, "not publishable"):
            builder.build_one(self.source, check_only=True)
        with patch.object(builder, "sign") as sign:
            with self.assertRaisesRegex(SystemExit, "not publishable"):
                builder.build_one(self.source)
            sign.assert_not_called()
        (self.source / "pack.toml").write_text(body.replace('libc = "musl"', 'libc = "other"'))
        with self.assertRaises(SystemExit):
            builder.parse_pack_toml(self.source / "pack.toml")


if __name__ == "__main__":
    unittest.main()
