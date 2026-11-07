"""Generated pack pages: content, safety and staleness."""

import hashlib
import json
import runpy
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pages = runpy.run_path(str(ROOT / "scripts" / "build-pack-pages.py"))
PageError = pages["PageError"]
generate = pages["generate"]
main = pages["main"]

PROFILE = """description = "policy"
[groups]
include = ["llm-apis", "github"]

[[overrides.secrets.bind]]
name = "anthropic"
hosts = ["api.example.test"]
value = "sk-SECRET-VALUE"
"""


def put_manifest(root, ns, name, version, manifest, files=None):
    directory = root / "packs" / ns / name / version
    directory.mkdir(parents=True)
    if files and manifest.get("schema_version") == 1:
        manifest = dict(manifest, files=[
            {"path": relative, "sha256": hashlib.sha256(text.encode()).hexdigest(),
             "size": len(text.encode())} for relative, text in files.items()])
    raw = json.dumps(manifest).encode()
    (directory / "manifest.json").write_bytes(raw)
    for relative, text in (files or {}).items():
        (directory / "files" / relative).parent.mkdir(parents=True, exist_ok=True)
        (directory / "files" / relative).write_text(text)
    return hashlib.sha256(raw).hexdigest()


def policy_manifest(ref):
    return {"schema_version": 1, "reference": ref, "description": "d", "files": []}


def app_manifest(ref):
    return {
        "schema_version": 2, "kind": "application", "reference": ref, "description": "d",
        "application": {
            "schema_version": 1, "guest_arch": "aarch64",
            "bundle": {"source": "https://bundles.example/a/app.mvmpkg",
                       "archive_sha256": "a" * 64, "archive_size": 123, "key_id": "b" * 32},
        },
    }


class PackPageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.revoked = []
        self.entries = []
        (self.root / "docs").mkdir()
        (self.root / "docs/publishing-a-pack.md").write_text("# Publish a policy pack\n")

    def add(self, ns, name, versions):
        """versions: list of (version, manifest, files), newest first."""
        item = {"namespace": ns, "name": name, "description": f"{name} pack", "versions": []}
        for version, manifest, files in versions:
            sha = put_manifest(self.root, ns, name, version, manifest, files)
            item["versions"].append({"version": version, "manifest_sha256": sha})
        self.entries.append(item)
        return item

    def finish(self):
        (self.root / "index.json").write_text(json.dumps({"schema_version": 2, "packs": self.entries}))
        (self.root / "revocations.toml").write_text(
            "schema_version = 1\nrevoked_identities = []\nrevoked_manifests = %s\n"
            % json.dumps(self.revoked))

    def test_policy_page_is_not_runnable_and_has_no_secret_value(self):
        self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), {"pack/profile.toml": PROFILE})])
        self.finish()
        page = generate(self.root)["agent/p.md"]
        self.assertIn("mvmctl pull agent/p@1.0.0", page)
        self.assertNotIn("mvmctl run", page)
        self.assertIn("is not runnable", page)
        self.assertIn("| `anthropic` | `api.example.test` |", page)
        self.assertIn("| Included group | `llm-apis` |", page)
        self.assertIn("a binding is not proof that a secret is required", page)
        self.assertNotIn("sk-SECRET-VALUE", "".join(generate(self.root).values()))
        self.assertTrue(page.startswith("<!-- generated"))

    def test_readme_is_from_manifest_pinned_payload(self):
        files = {"pack/profile.toml": PROFILE,
                 "pack/README.md": "## Setup\n\nUse this policy. <script>alert(1)</script>\n"}
        self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), files)])
        self.finish()
        page = generate(self.root)["agent/p.md"]
        self.assertIn("## About this pack\n\n## Setup\n\nUse this policy.", page)
        self.assertNotIn("<script>", page)
        (self.root / "packs/agent/p/1.0.0/files/pack/README.md").write_text("changed")
        with self.assertRaises(PageError):
            generate(self.root)

    def test_catalog_links_and_escapes_descriptions(self):
        item = self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), None)])
        item["description"] = "<script>alert(1)</script>"
        self.finish()
        result = generate(self.root)
        self.assertIn('href="agent/p.md"', result["README.md"])
        self.assertNotIn("<script>", result["README.md"])
        self.assertNotIn("<script>", result["agent/p.md"])
        self.assertIn("# Publish a policy pack", result["publish.md"])

    def test_application_page_shows_descriptor_and_defers_archive_fields(self):
        self.add("app", "a", [("1.0.0", app_manifest("app/a@1.0.0"), None)])
        self.finish()
        page = generate(self.root)["app/a.md"]
        self.assertIn("mvmctl run app/a", page)
        self.assertIn("| aarch64 | `" + "a" * 64 + "` | 123 | `" + "b" * 32 + "` |", page)
        self.assertIn("recorded in the signed archive; shown after `mvmctl pull`", page)
        self.assertNotIn("not runnable", page)
        self.assertIn("| `app/a` | application | `1.0.0` | aarch64 | 123 B |", page)
        self.assertIn("application · aarch64 · 123 B · latest 1.0.0", generate(self.root)["README.md"])

    def test_revoked_version_row(self):
        item = self.add("agent", "p", [
            ("1.0.1", policy_manifest("agent/p@1.0.1"), None),
            ("1.0.0", policy_manifest("agent/p@1.0.0"), None)])
        self.revoked = [item["versions"][1]["manifest_sha256"]]
        self.finish()
        page = generate(self.root)["agent/p.md"]
        self.assertRegex(page, r"\| `1\.0\.0` \| `[0-9a-f]{64}` \| yes \|")
        self.assertRegex(page, r"\| `1\.0\.1` \| `[0-9a-f]{64}` \| no \|")

    def test_current_identity_revocation_marks_every_version(self):
        ids = runpy.run_path(str(ROOT / "scripts" / "publisher_identity.py"))
        self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), None)])
        self.finish()
        self._revoke_ids([ids["CURRENT_IDENTITY"]])
        self.assertRegex(generate(self.root)["agent/p.md"], r"\| `[0-9a-f]{64}` \| yes \|")

    def _revoke_ids(self, identities):
        (self.root / "revocations.toml").write_text(
            "schema_version = 1\nrevoked_identities = %s\nrevoked_manifests = []\n"
            % json.dumps(identities))

    def test_malformed_manifest_is_refused(self):
        self.add("agent", "p", [("1.0.0", {"schema_version": 1, "reference": "agent/p@1.0.0"}, None)])
        self.finish()
        with self.assertRaises(PageError):
            generate(self.root)

    def test_manifest_not_matching_index_pin_is_refused(self):
        item = self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), None)])
        item["versions"][0]["manifest_sha256"] = "0" * 64
        self.finish()
        with self.assertRaises(PageError):
            generate(self.root)

    def test_output_order_is_deterministic(self):
        self.add("runtime", "z", [("1.0.0", policy_manifest("runtime/z@1.0.0"), None)])
        self.add("agent", "a", [("1.0.0", policy_manifest("agent/a@1.0.0"), None)])
        self.finish()
        first = generate(self.root)
        self.entries.reverse()
        self.finish()
        second = generate(self.root)
        self.assertEqual(first, second)
        index = first["README.md"]
        self.assertLess(index.index("agent/a"), index.index("runtime/z"))

    def test_check_detects_stale_and_extra_pages(self):
        self.add("agent", "p", [("1.0.0", policy_manifest("agent/p@1.0.0"), None)])
        self.finish()
        main([], root=self.root)
        main(["--check"], root=self.root)
        page = self.root / "docs" / "registry" / "agent" / "p.md"
        page.write_text(page.read_text() + "edit\n")
        with self.assertRaises(SystemExit):
            main(["--check"], root=self.root)
        main([], root=self.root)
        (self.root / "docs" / "registry" / "extra.md").write_text("x")
        with self.assertRaises(SystemExit):
            main(["--check"], root=self.root)

    def test_committed_pages_are_current(self):
        main(["--check"])


if __name__ == "__main__":
    unittest.main()
