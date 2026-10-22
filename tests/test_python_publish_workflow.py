"""The Python publisher signs only reproducible, pinned image evidence."""

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/publish.yml"
VALIDATE = ROOT / ".github/workflows/validate.yml"
RUNNER = ROOT / "scripts/run-python-image-publisher.sh"


class PythonPublishWorkflowTests(unittest.TestCase):
    def test_image_lane_is_manual_main_only_and_uses_the_publisher_identity(self):
        workflow = PUBLISH.read_text()
        image_job = workflow.split("  sign_python_image:\n", 1)[1].split(
            "\n  boot_python_image:\n", 1)[0]
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("mvmctl_tag:", workflow)
        self.assertIn("mvmctl_archive_sha256:", workflow)
        self.assertIn("image_inputs_sha256:", workflow)
        self.assertIn("MVM_IMAGE_INPUTS_SHA256: ${{ inputs.image_inputs_sha256 }}", image_job)
        self.assertIn("github.ref == 'refs/heads/main'", image_job)
        self.assertIn("github.event_name == 'workflow_dispatch'", image_job)
        self.assertIn("id-token: write", image_job)
        self.assertIn("contents: read", image_job)
        self.assertNotIn("contents: write", image_job)
        self.assertIn("run-python-image-publisher.sh", image_job)
        self.assertIn("actions/upload-artifact@", image_job)
        self.assertIn("path: ${{ runner.temp }}/signed-python-image/", image_job)
        self.assertNotIn("path: ${{ runner.temp }}/python-image-release-stage/", image_job)
        self.assertNotIn("git push origin HEAD:main", image_job)
        self.assertNotIn("python-candidate.yml", image_job)

    def test_reproduction_precedes_signing_without_release_or_registry_write(self):
        runner = RUNNER.read_text()
        ordered = (
            "fetch-released-mvmctl.sh",
            "fetch-current-images-lock.sh",
            "__builder-shell-job",
            "build-python-sidecar.py",
            "sign-composed-image.py",
            "check-python-composed-runtime.py",
            "stage-image-release.py",
        )
        positions = [runner.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("default-microvm-meta-x86_64.json", runner)
        self.assertIn('sidecar="${pack_source%/*}/mvm-meta.json"', runner)
        self.assertIn('--mvm-meta "$sidecar"', runner)
        self.assertIn('--expected-inputs-sha256 "$MVM_IMAGE_INPUTS_SHA256"', runner)
        self.assertIn('"$evidence/rootfs.ext4"', runner)
        self.assertIn('"$evidence/mvm-meta.json"', runner)
        self.assertIn('--evidence "$evidence"', runner)
        self.assertIn('--output "$release_stage"', runner)
        self.assertEqual(runner.count("stage-image-release.py"), 1)
        self.assertGreater(runner.rindex("assert_current_lock"),
                           runner.index("stage-image-release.py"))
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

    def test_complete_image_request_is_required_but_empty_catalogue_stays_valid(self):
        block = PUBLISH.read_text().split(
            "      - name: Require a complete image signing request\n", 1
        )[1].split("\n  sign:\n", 1)[0]
        script = textwrap.dedent(block.split("        run: |\n", 1)[1])
        cases = (
            ("", "", "", 0),
            ("v0.24.1-rc.1", "a" * 64, "b" * 64, 0),
            ("v0.24.1-rc.1", "a" * 64, "", 1),
            ("v0.24.1-rc.1", "", "b" * 64, 1),
            ("", "a" * 64, "b" * 64, 1),
            ("", "", "b" * 64, 1),
            ("v0.24.1-rc.1", "a" * 64, "B" * 64, 1),
        )
        for tag, archive, inputs, expected in cases:
            with self.subTest(tag=tag, archive=archive, inputs=inputs):
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    env={"GITHUB_EVENT_NAME": "workflow_dispatch", "MVMCTL_TAG": tag,
                         "MVMCTL_ARCHIVE_SHA256": archive, "MVM_IMAGE_INPUTS_SHA256": inputs},
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_missing_image_pin_refuses_before_any_download_or_builder(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["/bin/bash", str(RUNNER)],
                cwd=directory,
                env={"PATH": directory, "GITHUB_REF": "refs/heads/main",
                     "GITHUB_EVENT_NAME": "workflow_dispatch",
                     "MVMCTL_TAG": "v0.24.1-rc.1",
                     "MVMCTL_ARCHIVE_SHA256": "a" * 64, "RUNNER_TEMP": directory},
                capture_output=True, text=True, timeout=5,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_invalid_release_tag_refuses_before_release_download(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.update({
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "MVMCTL_TAG": "not-a-release",
                "MVMCTL_ARCHIVE_SHA256": "a" * 64,
                "RUNNER_TEMP": directory,
            })
            result = subprocess.run(
                ["bash", str(RUNNER)], cwd=directory, env=environment,
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Could not resolve", result.stderr)


if __name__ == "__main__":
    unittest.main()
