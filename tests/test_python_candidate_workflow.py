"""The candidate lane is read-only and cannot publish an image."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/python-candidate.yml"
RUNNER = ROOT / "scripts/run-python-image-builder.sh"


class PythonCandidateWorkflowTests(unittest.TestCase):
    def test_manual_lane_requires_signed_client_and_current_mvm_lock(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("  push:", workflow)
        self.assertNotIn("  schedule:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("    env:\n      GH_TOKEN:", workflow)
        self.assertEqual(workflow.count("GH_TOKEN: ${{ github.token }}"), 2)
        self.assertIn("cosign verify-blob", workflow)
        self.assertIn("checksums-sha256.txt.bundle", workflow)
        self.assertIn("crates/mvm-core/images.lock", workflow)
        self.assertIn("image-set.json.bundle", workflow)
        self.assertIn("__builder-shell-job", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("unsigned-python-image", workflow)
        self.assertNotIn("publish-image-pack.py", workflow)
        self.assertNotIn("upload-image-release.py", workflow)

    def test_builder_shell_script_requires_lock_and_all_reproduction_inputs(self):
        body = RUNNER.read_text()
        for required in (
            "build-python-image.py", "--mvm-images-lock", "--mvmctl-sha256-file",
            "--manifest", "--bundle", "--artifacts", "--output",
            "--no-update-lock-file", '"$python_output/bin/python3"',
        ):
            self.assertIn(required, body)
        subprocess.run(["sh", "-n", str(RUNNER)], check=True)

    def test_candidate_workflow_changes_run_pull_request_validation(self):
        validation = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn('".github/workflows/python-candidate.yml"', validation)


if __name__ == "__main__":
    unittest.main()
