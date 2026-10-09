"""The Python publisher signs only reproducible, pinned image evidence."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/publish.yml"
VALIDATE = ROOT / ".github/workflows/validate.yml"
RUNNER = ROOT / "scripts/run-python-image-publisher.sh"


class PythonPublishWorkflowTests(unittest.TestCase):
    def test_image_lane_is_manual_main_only_and_uses_the_publisher_identity(self):
        workflow = PUBLISH.read_text()
        image_job = workflow.split("  sign_python_image:\n", 1)[1]
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("mvmctl_tag:", workflow)
        self.assertIn("mvmctl_archive_sha256:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", image_job)
        self.assertIn("github.event_name == 'workflow_dispatch'", image_job)
        self.assertIn("id-token: write", image_job)
        self.assertIn("contents: read", image_job)
        self.assertNotIn("contents: write", image_job)
        self.assertIn("run-python-image-publisher.sh", image_job)
        self.assertIn("actions/upload-artifact@", image_job)
        self.assertNotIn("git push origin HEAD:main", image_job)
        self.assertNotIn("python-candidate.yml", image_job)

    def test_reproduction_precedes_signing_without_release_or_registry_write(self):
        runner = RUNNER.read_text()
        ordered = (
            "checksums-sha256.txt.bundle",
            "crates/mvm-core/images.lock",
            "__builder-shell-job",
            "check-python-base-entrypoint.py",
            "sign-composed-image.py",
        )
        positions = [runner.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("pack-sources/runtime/python/mvm-meta.json", runner)
        self.assertIn("assert_current_lock", runner)
        self.assertNotIn("upload-image-release.py", runner)
        self.assertNotIn("publish-image-pack.py", runner)
        self.assertNotIn("git push", runner)
        self.assertNotIn("git commit", runner)

    def test_entrypoint_inspection_tool_is_installed_for_the_signing_job(self):
        image_job = PUBLISH.read_text().split("  sign_python_image:\n", 1)[1]
        self.assertIn("apt-get install --yes e2fsprogs", image_job)

    def test_workflow_changes_trigger_pull_request_validation(self):
        self.assertIn('".github/workflows/publish.yml"', VALIDATE.read_text())

    def test_missing_boot_sidecar_refuses_before_release_download(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.update({
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "MVMCTL_TAG": "v0.23.1",
                "MVMCTL_ARCHIVE_SHA256": "a" * 64,
                "RUNNER_TEMP": directory,
            })
            result = subprocess.run(
                ["bash", str(RUNNER)], cwd=directory, env=environment,
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("boot sidecar is required before signing", result.stderr)


if __name__ == "__main__":
    unittest.main()
