"""Source-built client runs are read-only diagnostics, never publication evidence."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/python-source-diagnostic.yml"
VALIDATE = ROOT / ".github/workflows/validate.yml"


class PythonSourceDiagnosticWorkflowTests(unittest.TestCase):
    def test_manual_main_only_with_read_only_permissions(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("persist-credentials: false", workflow)

    def test_source_and_base_are_pinned_before_builder_execution(self):
        workflow = WORKFLOW.read_text()
        source = "e9b9d8c5876edb11c410728f8030f3678656adf9"
        self.assertIn(f"MVM_SOURCE_SHA: {source}", workflow)
        self.assertIn(f"ref: {source}", workflow)
        ordered = (
            "Require KVM for the project builder VM",
            "cargo zigbuild --profile release-min --target x86_64-unknown-linux-musl",
            "cmp crates/mvm-core/images.lock",
            "cosign verify-blob \"$release_dir/image-set.json\"",
            "__builder-shell-job",
            "test -s \"$output/python-image/composition/rootfs.ext4\"",
            "actions/upload-artifact@",
        )
        self.assertEqual([workflow.index(item) for item in ordered], sorted(
            workflow.index(item) for item in ordered
        ))

    def test_source_endpoint_is_built_and_explicitly_selected(self):
        workflow = WORKFLOW.read_text()
        helper_build = (
            "cargo zigbuild --profile release-min --target x86_64-unknown-linux-musl "
            "-p mvm-hostd --bin mvm-network-endpoint"
        )
        helper = "target/x86_64-unknown-linux-musl/release-min/mvm-network-endpoint"
        self.assertIn(helper_build, workflow)
        self.assertIn(f'endpoint={helper}', workflow)
        self.assertIn('test -x "$endpoint"', workflow)
        self.assertIn('MVM_SUBSTITUTION_ENDPOINT_PATH="$GITHUB_WORKSPACE/$endpoint"', workflow)
        self.assertLess(workflow.index(helper_build), workflow.index('__builder-shell-job'))

    def test_unsigned_diagnostic_cannot_sign_or_publish(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("unsigned-source-python-image-", workflow)
        self.assertIn("retention-days: 3", workflow)
        for forbidden in (
            "sign-composed-image.py", "upload-image-release.py", "publish-image-pack.py",
            "gh release create", "git push", "git commit", "id-token: write",
        ):
            self.assertNotIn(forbidden, workflow)
        self.assertIn('".github/workflows/python-source-diagnostic.yml"', VALIDATE.read_text())


if __name__ == "__main__":
    unittest.main()
