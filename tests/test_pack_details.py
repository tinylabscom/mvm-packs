import copy
import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pack_details  # noqa: E402
from tests.test_application_manifest import TEST_KEY_ID, TEST_PUBLIC, make_mvmpkg, application  # noqa: E402
from tests.test_publisher_verification import builder, validator  # noqa: E402

pages = runpy.run_path(str(ROOT / "scripts" / "build-pack-pages.py"))
PageError, generate = pages["PageError"], pages["generate"]

ENVIRONMENT = {"class": "environment", "descriptor_version": 1, "target": "aarch64-linux",
               "pack": {"name": "acme/tool", "version": "1.0.0"},
               "entrypoint": {"argv": ["/etc/mvm/entrypoint"]}, "resources": {"cpu_cores": 2, "memory_mb": 4096},
               "policy": {"allow_hosts": ["api.example.com:443"]},
               "secret_slots": [{"name": "API_KEY", "required": True}], "capabilities": ["egress"]}


def details(**changes):
    base = {"schema_version": 1, "reference": "acme/tool@1.0.0",
            "archive": {"sha256": "a" * 64, "size": 123, "key_id": "b" * 32, "arch": "aarch64"},
            "created_at": "2026-11-06T00:00:00+00:00",
            "artifacts": [{"name": "vmlinux", "role": "kernel", "size_bytes": 6, "sha256": "c" * 64}],
            "runtime": [{"class": "embedded_cli_boot_assets", "version": "0.24.0"}],
            "environment": {k: v for k, v in ENVIRONMENT.items() if k != "class"},
            "binaries": [{"package": "tool", "path": "bin/tool", "sha256": "d" * 64, "size": 9}]}
    return base | changes


class ValidateTests(unittest.TestCase):
    def test_a_recorded_shape_passes_and_every_deviation_is_refused(self):
        pack_details.validate(details())
        bad = {
            "extra field": details(extra=1),
            "bad reference": details(reference="not a reference"),
            "bad digest": details(archive={"sha256": "A" * 64, "size": 1, "key_id": "b" * 32, "arch": "aarch64"}),
            "bad arch": details(archive={"sha256": "a" * 64, "size": 1, "key_id": "b" * 32, "arch": "arm"}),
            "no artifacts": details(artifacts=[]),
            "bad artifact": details(artifacts=[{"name": "x", "role": "kernel", "size_bytes": -1, "sha256": "c" * 64}]),
            "unknown environment field": details(environment={"secrets": {"k": "v"}}),
            "huge environment": details(environment={"policy": {"a": "x" * 5000}}),
            "bad binary": details(binaries=[{"package": "t", "path": "p", "sha256": "z", "size": 1}]),
            "long created": details(created_at="x" * 100),
        }
        for label, value in bad.items():
            with self.subTest(label), self.assertRaises(ValueError):
                pack_details.validate(value)

    def test_untrusted_text_cannot_break_out_of_a_page(self):
        evil = details(environment={"entrypoint": {"argv": ["`</td><script>alert(1)</script>\n|"]}},
                       artifacts=[{"name": "a`b|\n", "role": "kernel", "size_bytes": 1, "sha256": "c" * 64}])
        text = "".join(pack_details.render(evil))
        self.assertNotIn("`</td>", text)
        self.assertNotIn("a`b", text)
        self.assertEqual(pack_details.code("x" * 500)[1:-1], "x" * 200)
        self.assertNotIn("\n", pack_details.code("a\nb\x00c"))


class GateTests(unittest.TestCase):
    def test_the_gate_returns_what_it_saw(self):
        import io
        members = [dict(ENVIRONMENT), {"class": "embedded_cli_boot_assets", "version": "0.24.0"}]
        data = make_mvmpkg(members=members)
        import hashlib
        app = application()
        app["bundle"] |= {"archive_size": len(data), "archive_sha256": hashlib.sha256(data).hexdigest(),
                          "key_id": TEST_KEY_ID}

        def serve(url, timeout=None):
            return io.BytesIO(TEST_PUBLIC if url.endswith("-bundle-publisher.pub") else data)

        with patch.object(builder.urllib.request, "urlopen", side_effect=serve):
            seen = builder.verify_archive(app)
        self.assertEqual(seen["archive"]["sha256"], app["bundle"]["archive_sha256"])
        self.assertEqual(seen["environment"]["policy"], {"allow_hosts": ["api.example.com:443"]})
        self.assertEqual(seen["runtime"], [{"class": "embedded_cli_boot_assets", "version": "0.24.0"}])
        self.assertEqual({a["role"] for a in seen["artifacts"]}, {"kernel", "rootfs"})
        pack_details.validate(dict(seen, reference="acme/tool@1.0.0"))

    def test_recording_is_informational_and_atomic(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(builder, "DETAILS", Path(tmp)):
            builder.write_details("acme", "tool", "1.0.0", details(reference=None))
            written = json.loads((Path(tmp) / "acme/tool/1.0.0.json").read_text())
            self.assertEqual(written["reference"], "acme/tool@1.0.0")
            self.assertEqual(list(Path(tmp).rglob("*.tmp")), [])
            builder.write_details("acme", "bad", "1.0.0", {"schema_version": 1})   # invalid: prints, never raises
            self.assertFalse((Path(tmp) / "acme/bad").exists())


class PageAndValidatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        manifest = {"schema_version": 2, "kind": "application", "reference": "acme/tool@1.0.0", "description": "d",
                    "application": {"schema_version": 1, "guest_arch": "aarch64",
                                    "bundle": {"source": "https://b.example/t.mvmpkg", "archive_sha256": "a" * 64,
                                               "archive_size": 123, "key_id": "b" * 32}}}
        directory = self.root / "packs/acme/tool/1.0.0"
        directory.mkdir(parents=True)
        raw = json.dumps(manifest).encode()
        (directory / "manifest.json").write_bytes(raw)
        import hashlib
        index = {"schema_version": 2, "packs": [{"namespace": "acme", "name": "tool", "description": "d", "versions": [
            {"version": "1.0.0", "manifest_sha256": hashlib.sha256(raw).hexdigest()}]}]}
        (self.root / "index.json").write_text(json.dumps(index))
        (self.root / "revocations.toml").write_text(
            "schema_version = 1\nrevoked_identities = []\nrevoked_manifests = []\n")
        (self.root / "docs").mkdir()
        (self.root / "docs/publishing-a-pack.md").write_text("# Publish\n")

    def put(self, value):
        path = self.root / "pack-details/acme/tool/1.0.0.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_a_page_shows_recorded_details_or_the_pull_notice(self):
        self.assertIn("shown after `mvmctl pull`", generate(self.root)["acme/tool.md"])
        self.put(details())
        page = generate(self.root)["acme/tool.md"]
        self.assertIn("## Recorded at signing", page)
        self.assertIn("`/etc/mvm/entrypoint`", page)
        self.assertIn("API_KEY (required)", page)
        self.assertIn("not signed registry metadata", page)

    def test_details_that_do_not_match_the_descriptor_stop_the_page_build(self):
        wrong = details(archive={"sha256": "e" * 64, "size": 123, "key_id": "b" * 32, "arch": "aarch64"})
        self.put(wrong)
        with self.assertRaises(PageError):
            generate(self.root)

    def test_the_validator_accepts_matching_details_and_refuses_stray_or_mismatched_files(self):
        def run():
            validator.problems.clear()
            with patch.object(validator, "ROOT", self.root), patch.object(validator, "PACKS", self.root / "packs"):
                validator.validate_details()
            return list(validator.problems)

        self.put(details())
        self.assertEqual(run(), [])
        self.put(details(archive={"sha256": "e" * 64, "size": 123, "key_id": "b" * 32, "arch": "aarch64"}))
        self.assertTrue(run())
        self.put(details())
        (self.root / "pack-details/stray.txt").write_text("x")
        self.assertTrue(run())
        validator.problems.clear()
