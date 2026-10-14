"""The signed Python image reaches release and registry only through each gate."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/publish.yml"
BOOT = ROOT / "scripts/run-python-image-boot-probe.sh"
FETCH_CLIENT = ROOT / "scripts/fetch-released-mvmctl.sh"
COMMIT = ROOT / "scripts/commit-image-pack.sh"
IMAGE_JOBS = ("sign_python_image", "boot_python_image", "release_python_image",
              "publish_python_pack")


def jobs(workflow):
    """Split the workflow into top-level job bodies keyed by job id."""
    body = workflow.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z_]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def permissions(job):
    block = job.split("    permissions:\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if not line.startswith("      "):
            break
        lines.append(line.strip())
    return lines


class PublicationLaneWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = PUBLISH.read_text()
        self.jobs = jobs(self.workflow)

    def test_lanes_run_in_order_only_for_a_main_dispatch(self):
        expected_needs = {
            "boot_python_image": "sign_python_image",
            "release_python_image": "boot_python_image",
            "publish_python_pack": "release_python_image",
        }
        for job, needs in expected_needs.items():
            with self.subTest(job=job):
                body = self.jobs[job]
                self.assertIn(f"    needs: {needs}\n", body)
                self.assertIn("github.ref == 'refs/heads/main'", body)
                self.assertIn("github.event_name == 'workflow_dispatch'", body)
                self.assertIn("inputs.mvmctl_tag != ''", body)

    def test_each_lane_has_least_privilege(self):
        self.assertIn("\npermissions: {}\n", self.workflow)
        expected = {
            "sign_python_image": ["contents: read", "id-token: write"],
            "boot_python_image": ["contents: read"],
            "release_python_image": ["contents: write"],
            "publish_python_pack": ["contents: write", "id-token: write"],
        }
        for job, granted in expected.items():
            with self.subTest(job=job):
                self.assertEqual(permissions(self.jobs[job]), granted)

    def test_every_action_is_pinned_by_commit(self):
        for line in self.workflow.splitlines():
            if "uses:" in line:
                with self.subTest(line=line):
                    self.assertRegex(line, r"uses: [\w./-]+@[0-9a-f]{40}(\s|$)")

    def test_later_lanes_reverify_the_downloaded_evidence(self):
        artifact = "name: signed-python-image-${{ github.run_id }}"
        for job in IMAGE_JOBS[1:]:
            with self.subTest(job=job):
                body = self.jobs[job]
                self.assertIn("actions/download-artifact@", body)
                self.assertIn(artifact, body)
        for job in ("release_python_image", "publish_python_pack"):
            self.assertNotIn("actions/upload-artifact@", self.jobs[job])
        boot = BOOT.read_text()
        self.assertIn("scripts/run-python-image-boot-probe.sh", self.jobs["boot_python_image"])
        self.assertLess(boot.index("fetch-released-mvmctl.sh"),
                        boot.index("stage-image-release.py"))
        self.assertLess(boot.index("fetch-current-images-lock.sh"),
                        boot.index("stage-image-release.py"))
        self.assertLess(boot.index("stage-image-release.py"), boot.index(" run --deployment"))
        self.assertIn("scripts/upload-image-release.py", self.jobs["release_python_image"])
        self.assertIn("scripts/publish-image-pack.py", self.jobs["publish_python_pack"])
        for job in ("release_python_image", "publish_python_pack"):
            self.assertIn("fetch-current-images-lock.sh", self.jobs[job])

    def test_boot_lane_runs_the_released_client_on_kvm_and_keeps_its_record(self):
        body = self.jobs["boot_python_image"]
        self.assertIn("runs-on: ubuntu-24.04", body)
        self.assertIn("test -c /dev/kvm", body)
        self.assertIn("if: always()", body)
        self.assertIn("name: python-image-boot-probe-${{ github.run_id }}", body)
        boot = BOOT.read_text()
        self.assertIn('"$binary" bootstrap', boot)
        self.assertIn('run --deployment "$deployment" --timeout 120', boot)
        self.assertIn("command=(/bin/python3 --version)", boot)
        self.assertIn("timeout --kill-after=30 600", boot)
        self.assertLess(boot.index(" run --deployment"),
                        boot.index("check-python-boot-probe.py"))
        self.assertNotIn("MVM_DIRECT_BOOT", boot)
        self.assertNotIn("--profile dev", boot)

    def test_only_the_registry_lane_writes_main(self):
        for job, body in self.jobs.items():
            if job in ("publish", "publish_python_pack"):
                continue
            with self.subTest(job=job):
                self.assertNotIn("git push", body)
                self.assertNotIn("commit-image-pack.sh", body)
        self.assertIn("commit-image-pack.sh", self.jobs["publish_python_pack"])
        self.assertIn("fetch-depth: 0", self.jobs["publish_python_pack"])
        self.assertIn("validate-packs.py --verify-signatures --require-revocations",
                      self.jobs["publish_python_pack"])

    def test_publishers_share_one_concurrency_group(self):
        self.assertIn("concurrency:\n  group: signed-pack-publisher\n"
                      "  cancel-in-progress: false\n", self.workflow)

    def test_release_lane_cannot_sign(self):
        body = self.jobs["release_python_image"]
        self.assertNotIn("id-token", body)
        self.assertNotIn("COSIGN_YES", body)
        self.assertIn("persist-credentials: false", body)


class FetchReleasedClientTests(unittest.TestCase):
    def test_invalid_dispatch_refuses_before_download(self):
        for tag, digest in (("not-a-release", "a" * 64), ("v0.24.0", "A" * 64)):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as directory:
                environment = {**os.environ, "MVMCTL_TAG": tag,
                               "MVMCTL_ARCHIVE_SHA256": digest,
                               "RUNNER_TEMP": directory, "PATH": "/usr/bin:/bin"}
                result = subprocess.run(["bash", str(FETCH_CLIENT)], cwd=directory,
                                        env=environment, capture_output=True,
                                        text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(Path(directory, "mvmctl-release").exists())

    def test_client_is_authenticated_before_it_runs(self):
        script = FETCH_CLIENT.read_text()
        self.assertIn("release.yml@refs/tags/${MVMCTL_TAG}", script)
        ordered = ("cosign verify-blob", 'test "$actual" = "$expected"',
                   'test "$actual" = "$MVMCTL_ARCHIVE_SHA256"', "tar -C",
                   '"$binary" --version')
        positions = [script.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))


@unittest.skipUnless(shutil.which("git"), "git is required")
class CommitImagePackTests(unittest.TestCase):
    """Run the commit script against a throwaway origin with stub validators."""

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.work, check=True,
                              capture_output=True, text=True).stdout

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.origin = root / "origin.git"
        self.work = root / "work"
        subprocess.run(["git", "init", "--bare", "-b", "main", str(self.origin)],
                       check=True, capture_output=True)
        subprocess.run(["git", "clone", str(self.origin), str(self.work)],
                       check=True, capture_output=True)
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.work / "scripts").mkdir()
        (self.work / "scripts/build-packs.py").write_text(
            "from pathlib import Path\n"
            "def rebuild_index():\n"
            "    names = sorted(str(p.parent.relative_to('packs'))\n"
            "                   for p in Path('packs').rglob('manifest.json'))\n"
            "    Path('packs/index.json').write_text('\\n'.join(names) + '\\n')\n"
            "    Path('index.json').write_bytes(Path('packs/index.json').read_bytes())\n")
        (self.work / "scripts/validate-packs.py").write_text(
            "import pathlib, sys\n"
            "pathlib.Path('validated').write_text(' '.join(sys.argv[1:]))\n")
        source = self.work / "pack-sources/runtime/python"
        source.mkdir(parents=True)
        (source / "pack.toml").write_text('version = "1.1.0"\n')
        (self.work / "packs/runtime/python/1.0.0").mkdir(parents=True)
        (self.work / "packs/runtime/python/1.0.0/manifest.json").write_text("{}")
        (self.work / "packs/index.json").write_text("runtime/python/1.0.0\n")
        (self.work / "index.json").write_text("runtime/python/1.0.0\n")
        (self.work / ".gitignore").write_text("validated\n")
        self.git("add", ".")
        self.git("commit", "-m", "initial")
        self.git("push", "origin", "main")

    def add_version(self):
        target = self.work / "packs/runtime/python/1.1.0"
        target.mkdir()
        (target / "manifest.json").write_text("{}")
        (target / "manifest.sigstore.json").write_text("{}")
        (self.work / "packs/index.json").write_text(
            "runtime/python/1.0.0\nruntime/python/1.1.0\n")
        (self.work / "index.json").write_bytes((self.work / "packs/index.json").read_bytes())

    def run_commit(self):
        return subprocess.run(["bash", str(COMMIT), "pack-sources/runtime/python"],
                              cwd=self.work, capture_output=True, text=True,
                              check=False)

    def origin_files(self):
        return self.git("ls-tree", "-r", "--name-only", "main", cwd=self.origin)

    def test_new_version_is_pushed_as_one_commit(self):
        self.add_version()
        result = self.run_commit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("packs/runtime/python/1.1.0/manifest.sigstore.json",
                      self.origin_files())
        self.assertEqual(
            self.git("show", "main:index.json", cwd=self.origin),
            self.git("show", "main:packs/index.json", cwd=self.origin),
        )
        message = self.git("log", "-1", "--format=%s", "main", cwd=self.origin)
        self.assertIn("runtime/python@1.1.0", message)
        self.assertIn("[skip ci]", message)

    def test_unrelated_change_refuses_without_push(self):
        self.add_version()
        (self.work / "scripts/build-packs.py").write_text("changed\n")
        result = self.run_commit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected", result.stderr)
        self.assertNotIn("1.1.0", self.origin_files())

    def test_missing_signature_refuses(self):
        self.add_version()
        (self.work / "packs/runtime/python/1.1.0/manifest.sigstore.json").unlink()
        result = self.run_commit()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("1.1.0", self.origin_files())

    def test_moved_main_is_rebased_reindexed_and_revalidated(self):
        other = Path(self.temp.name) / "other"
        subprocess.run(["git", "clone", str(self.origin), str(other)], check=True,
                       capture_output=True)
        for key, value in (("user.name", "Other"), ("user.email", "o@example.invalid"),
                           ("commit.gpgsign", "false")):
            self.git("config", key, value, cwd=other)
        (other / "README").write_text("moved\n")
        self.git("add", "README", cwd=other)
        self.git("commit", "-m", "unrelated", cwd=other)
        self.git("push", "origin", "main", cwd=other)
        self.add_version()
        result = self.run_commit()
        self.assertEqual(result.returncode, 0, result.stderr)
        files = self.origin_files()
        self.assertIn("README", files)
        self.assertIn("packs/runtime/python/1.1.0/manifest.json", files)
        self.assertEqual((self.work / "validated").read_text(),
                         "--verify-signatures --require-revocations")

    def test_moved_main_with_a_conflicting_index_refuses(self):
        other = Path(self.temp.name) / "other"
        subprocess.run(["git", "clone", str(self.origin), str(other)], check=True,
                       capture_output=True)
        for key, value in (("user.name", "Other"), ("user.email", "o@example.invalid"),
                           ("commit.gpgsign", "false")):
            self.git("config", key, value, cwd=other)
        (other / "packs/index.json").write_text("runtime/python/1.0.0\nagent/x/1.0.0\n")
        self.git("commit", "-am", "other pack", cwd=other)
        self.git("push", "origin", "main", cwd=other)
        before = self.git("rev-parse", "main", cwd=self.origin)
        self.add_version()
        result = self.run_commit()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git("rev-parse", "main", cwd=self.origin), before)


if __name__ == "__main__":
    unittest.main()
