"""Review-bound publication must not update the default branch directly."""

import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/open-review-pr.sh"
WORKFLOWS = ROOT / ".github/workflows"


class ReviewPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.remote = root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.checkout / "index.json").write_text('{"old":true}\n')
        self.git("add", "index.json")
        self.git("commit", "-m", "initial")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "main")
        self.original_main = self.git("rev-parse", "HEAD").stdout.strip()

        bin_dir = root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['MOCK_GH_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
        )
        gh.chmod(0o755)
        self.log = root / "gh.json"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "1",
            "GH_TOKEN": "fixture-token",
            "MOCK_GH_LOG": str(self.log),
        }
        (self.checkout / "index.json").write_text('{"new":true}\n')
        self.git("add", "index.json")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.checkout, capture_output=True, text=True, check=True
        )

    def run_script(self, env=None):
        return subprocess.run(
            ["bash", str(SCRIPT), "packs", "Review publication", "Verify signed bytes"],
            cwd=self.checkout, env=env or self.env, capture_output=True, text=True,
        )

    def test_changes_are_proposed_on_a_new_branch_without_pushing_main(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/main").stdout.split()[0],
                         self.original_main)
        branch = "refs/heads/automation/packs-1234-1"
        self.assertNotEqual(self.git("ls-remote", "origin", branch).stdout.split()[0],
                            self.original_main)
        self.assertEqual(json.loads(self.log.read_text()), [
            "pr", "create", "--base", "main", "--head", "automation/packs-1234-1",
            "--title", "Review publication", "--body", "Verify signed bytes",
        ])

    def supersede_gh(self, close_fails=False):
        """A gh that records every call, lists fixture PRs through real jq, and creates PR 99."""
        listing = [
            {"number": 10, "headRefName": "automation/packs-1-1", "isCrossRepository": False},
            {"number": 11, "headRefName": "automation/packs-2-1", "isCrossRepository": False},
            {"number": 12, "headRefName": "automation/community-3-1", "isCrossRepository": False},
            {"number": 13, "headRefName": "automation/packs-4-1-extra", "isCrossRepository": False},
            {"number": 14, "headRefName": "feature/automation/packs-5-1", "isCrossRepository": False},
            {"number": 15, "headRefName": "automation/packs-6-1", "isCrossRepository": True},
            {"number": 99, "headRefName": "automation/packs-1234-1", "isCrossRepository": False},
        ]
        gh = Path(self.env["PATH"].split(os.pathsep)[0]) / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, subprocess, sys\n"
            "a = sys.argv[1:]\n"
            "open(os.environ['MOCK_GH_LOG'], 'a').write(json.dumps(a) + '\\n')\n"
            "if a[:2] == ['pr', 'create']:\n"
            "    print('https://github.com/o/r/pull/99')\n"
            "elif a[:2] == ['pr', 'list']:\n"
            f"    data = {json.dumps(listing)!r}\n"
            "    sys.stdout.write(subprocess.run(['jq', '-r', a[a.index('--jq') + 1]],\n"
            "        input=data, capture_output=True, text=True, check=True).stdout)\n"
            f"elif a[:2] == ['pr', 'close'] and {close_fails!r}:\n"
            "    sys.exit(1)\n"
        )
        self.log.unlink(missing_ok=True)

    def closed(self):
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [c[2] for c in calls if c[:2] == ["pr", "close"]], calls

    @unittest.skipUnless(shutil.which("jq"), "jq is required to evaluate the gh filter")
    def test_only_older_same_kind_automation_prs_are_closed(self):
        self.supersede_gh()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        closed, calls = self.closed()
        self.assertEqual(closed, ["10", "11"])
        for call in calls:
            if call[:2] == ["pr", "close"]:
                self.assertIn("--delete-branch", call)
                self.assertIn("Superseded by #99", call[-1])

    @unittest.skipUnless(shutil.which("jq"), "jq is required to evaluate the gh filter")
    def test_close_failure_does_not_fail_the_run(self):
        self.supersede_gh(close_fails=True)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.closed()[0], ["10", "11"])
        self.assertIn("could not close superseded pull request #10", result.stderr)

    def test_invalid_run_identity_refuses_before_publishing(self):
        for key, value in [("GITHUB_REF", "refs/heads/other"),
                           ("GITHUB_RUN_ID", "../wrong")]:
            with self.subTest(key=key):
                result = self.run_script(self.env | {key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.git("ls-remote", "origin").stdout.count("refs/heads/"), 1)
                self.assertFalse(self.log.exists())

    def test_workflows_use_review_and_validate_merge_groups(self):
        for name in ("publish.yml", "community-intake.yml"):
            source = (WORKFLOWS / name).read_text()
            self.assertIn("scripts/open-review-pr.sh", source)
            self.assertNotIn("git push origin HEAD:main", source)
            self.assertIn("actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
                          source)
            self.assertIn("GH_TOKEN: ${{ steps.review-token.outputs.token }}", source)
            self.assertIn("permission-contents: write", source)
            self.assertIn("permission-pull-requests: write", source)
        validation = (WORKFLOWS / "validate.yml").read_text()
        self.assertIn("  merge_group:", validation)
        self.assertIn("github.event_name == 'pull_request'", validation)
