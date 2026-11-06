import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
intake = runpy.run_path(str(ROOT / "scripts" / "community_intake.py"))
resolve = intake["resolve"]

REPO = "acme/packs"
REFERENCE = ('repository = "acme/packs"\nworkflow = ".github/workflows/p.yml"\n'
             'ref = "refs/heads/main"\npacks = ["tool"]\n')
URL = f"https://github.com/{REPO}/releases/download/"


def manifest(version="1.0.0", **changes):
    value = {"schema_version": 2, "kind": "application", "reference": f"acme/tool@{version}",
             "description": "A tool", "application": {
                 "schema_version": 1, "guest_arch": "aarch64",
                 "bundle": {"source": "https://bundles.example/t.mvmpkg", "archive_sha256": "a" * 64,
                            "archive_size": 9, "key_id": "b" * 32}}}
    return json.dumps(value | changes, sort_keys=True).encode()


def release(tag, **flags):
    return {"tag_name": tag, "draft": False, "prerelease": False, "assets": [
        {"name": "tool.manifest.json", "browser_download_url": f"{URL}{tag}/tool.manifest.json"},
        {"name": "tool.manifest.sigstore.json", "browser_download_url": f"{URL}{tag}/tool.manifest.sigstore.json"},
    ]} | flags


class IntakeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        publishers = self.root / "community" / "publishers"
        publishers.mkdir(parents=True)
        (publishers / "acme.toml").write_text(REFERENCE)
        self.releases = []
        self.files = {}
        self.read_back_calls = []
        self.verified = True

    def run_intake(self):
        def fetch(url):
            return self.files[url]
        return resolve(self.root, lambda repo: self.releases if repo == REPO else [], fetch,
                       lambda m, b, identity: self.verified and identity ==
                       f"https://github.com/{REPO}/.github/workflows/p.yml@refs/heads/main",
                       lambda bundle: self.read_back_calls.append(bundle))

    def add(self, tag, version, **changes):
        self.releases.append(release(tag))
        self.files[f"{URL}{tag}/tool.manifest.json"] = manifest(version, **changes)
        self.files[f"{URL}{tag}/tool.manifest.sigstore.json"] = b"{}"

    def index(self):
        return json.loads((self.root / "community" / "index.json").read_text())

    def test_lists_a_verified_release_and_copies_the_files(self):
        self.add("v1.0.0", "1.0.0")
        report = self.run_intake()
        self.assertIn("acme/tool@1.0.0: listed", report)
        pack = self.index()["packs"][0]
        self.assertEqual(pack["versions"][0]["tags"], ["latest"])
        self.assertEqual(pack["versions"][0]["guest_arch"], "aarch64")
        self.assertTrue((self.root / "community/packs/acme/tool/1.0.0/manifest.json").is_file())
        self.assertEqual(len(self.read_back_calls), 1)

    def test_latest_follows_the_highest_version_and_existing_versions_are_not_read_back_again(self):
        self.add("v1.0.0", "1.0.0")
        self.run_intake()
        self.add("v1.1.0", "1.1.0")
        self.run_intake()
        versions = self.index()["packs"][0]["versions"]
        self.assertEqual([v["version"] for v in versions], ["1.1.0", "1.0.0"])
        self.assertEqual([v.get("tags") for v in versions], [["latest"], None])
        self.assertEqual(len(self.read_back_calls), 2)  # 1.0.0 once, 1.1.0 once

    def test_bad_releases_are_skipped_and_never_listed(self):
        self.add("v1.0.0", "1.0.0", reference="acme/other@1.0.0")      # wrong reference
        self.releases.append(release("v2", draft=True))                  # draft
        self.releases.append(release("v3", prerelease=True))             # prerelease
        outside = release("v4")
        outside["assets"][0]["browser_download_url"] = "https://evil.example/tool.manifest.json"
        self.releases.append(outside)
        report = self.run_intake()
        self.assertEqual(self.index()["packs"], [])
        self.assertTrue(any("skipped" in line for line in report))
        self.assertTrue(any("outside the repository" in line for line in report))
        self.assertFalse((self.root / "community/packs").exists())

    def test_policy_packs_and_unverified_signatures_are_skipped(self):
        self.add("v1.0.0", "1.0.0")
        self.verified = False
        self.run_intake()
        self.assertEqual(self.index()["packs"], [])
        self.assertFalse((self.root / "community/packs/acme/tool/1.0.0").exists())
        self.verified = True
        self.files[f"{URL}v1.0.0/tool.manifest.json"] = json.dumps(
            {"schema_version": 1, "reference": "acme/tool@1.0.0", "description": "d", "files": []}).encode()
        report = self.run_intake()
        self.assertTrue(any("only application descriptors" in line for line in report))

    def test_failed_archive_read_back_blocks_listing(self):
        self.add("v1.0.0", "1.0.0")
        def refuse(bundle):
            raise ValueError("archive SHA-256 does not match the descriptor")
        report = resolve(self.root, lambda repo: self.releases, lambda url: self.files[url],
                         lambda m, b, i: True, refuse)
        self.assertEqual(json.loads((self.root / "community/index.json").read_text())["packs"], [])
        self.assertTrue(any("does not match the descriptor" in line for line in report))
        self.assertFalse((self.root / "community/packs/acme/tool/1.0.0").exists())

    def test_changed_released_bytes_are_refused_and_changed_identity_delists(self):
        self.add("v1.0.0", "1.0.0")
        self.run_intake()
        self.files[f"{URL}v1.0.0/tool.manifest.json"] = manifest("1.0.0", description="changed")
        report = self.run_intake()
        self.assertTrue(any("REFUSED" in line for line in report))
        self.assertEqual(self.index()["packs"][0]["description"], "A tool")
        (self.root / "community/publishers/acme.toml").write_text(
            REFERENCE.replace("p.yml", "other.yml"))
        report = self.run_intake()
        self.assertEqual(self.index()["packs"], [])
        self.assertTrue(any("delisted" in line for line in report))

    def test_bad_reference_file_stops_everything(self):
        (self.root / "community/publishers/agent.toml").write_text(REFERENCE.replace("acme", "agent"))
        report = self.run_intake()
        self.assertTrue(report and report[0].startswith("reference error"))
        self.assertFalse((self.root / "community/index.json").exists())
