"""Run the dedicated upload shell against a filesystem-only GitHub CLI mock."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/registry-pack-revocations.yml"
MOCK_GH = """#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
release = pathlib.Path(os.environ["MOCK_RELEASE"])
operation = args[1]
if operation == "view":
    print(json.dumps(sorted(p.name for p in release.iterdir())))
elif operation == "upload":
    files = args[3:]
    files.remove("--repo")
    files.remove(os.environ["GITHUB_REPOSITORY"])
    clobber = "--clobber" in files
    if clobber:
        files.remove("--clobber")
    for argument in files:
        # gh treats # as a display label, not an asset filename override.
        source, _, label = argument.partition("#")
        source = pathlib.Path(source)
        target = release / source.name
        if target.exists() and not clobber:
            sys.exit("asset already exists")
        shutil.copyfile(source, target)
        with open(os.environ["MOCK_LOG"], "a") as log:
            log.write(json.dumps([source.name, clobber, label]) + "\\n")
elif operation == "download":
    name = args[args.index("--pattern") + 1]
    directory = pathlib.Path(args[args.index("--dir") + 1])
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    if target.exists():
        sys.exit("download destination already exists")
    shutil.copyfile(release / name, target)
else:
    sys.exit("unexpected gh operation")
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "requires bash and jq")
class RevocationUploadWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "sequence").write_text("1\n")
        (candidate / "revocations.json").write_bytes(b'{"sequence":1}\n')
        (candidate / "revocations.sigstore.json").write_bytes(b"signed bundle\n")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(MOCK_GH)
        gh.chmod(0o755)
        self.log = self.root / "uploads.jsonl"
        self.env = {
            **os.environ,
            "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(self.root),
            "MOCK_RELEASE": str(self.release),
            "MOCK_LOG": str(self.log),
            "GITHUB_REPOSITORY": "test/private-mock",
            "RELEASE_TAG": "registry-pack-revocations",
        }
        step = WORKFLOW.read_text().split(
            "      - name: Publish immutable sequence pair then refresh aliases\n", 1
        )[1]
        run = step.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        self.script = "\n".join(line[10:] for line in run.splitlines())

    def run_step(self, runner_temp=None):
        env = dict(self.env)
        if runner_temp is not None:
            env["RUNNER_TEMP"] = str(runner_temp)
        return subprocess.run(
            ["bash", "-c", self.script], env=env, capture_output=True, text=True
        )

    def uploads(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_real_numbered_basenames_uploaded_first_aliases_clobbered_last(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.uploads(), [
            ["revocations-1.json", False, ""],
            ["revocations-1.sigstore.json", False, ""],
            ["revocations.json", True, ""],
            ["revocations.sigstore.json", True, ""],
        ])
        self.assertEqual(sorted(p.name for p in self.release.iterdir()), [
            "revocations-1.json", "revocations-1.sigstore.json",
            "revocations.json", "revocations.sigstore.json",
        ])
        for name in ("revocations.json", "revocations.sigstore.json"):
            self.assertEqual((self.release / name).read_bytes(),
                             (self.root / "candidate" / name).read_bytes())
            numbered = name.replace("revocations", "revocations-1", 1)
            self.assertEqual((self.release / numbered).read_bytes(),
                             (self.root / "candidate" / name).read_bytes())
        self.log.write_text("")
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.uploads(), [
            ["revocations.json", True, ""], ["revocations.sigstore.json", True, ""],
        ])

    def test_mock_models_label_as_label_not_filename(self):
        document = self.root / "candidate/revocations.json"
        result = subprocess.run(
            ["gh", "release", "upload", self.env["RELEASE_TAG"],
             "--repo", self.env["GITHUB_REPOSITORY"],
             f"{document}#revocations-1.json"],
            env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.uploads(), [["revocations.json", False, "revocations-1.json"]])
        self.assertTrue((self.release / "revocations.json").exists())
        self.assertFalse((self.release / "revocations-1.json").exists())

    def test_existing_immutable_mismatch_stops_before_alias_upload(self):
        for name in ("revocations-1.json", "revocations-1.sigstore.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as runner:
                shutil.copytree(self.root / "candidate", Path(runner) / "candidate")
                for path in self.release.iterdir():
                    path.unlink()
                if self.log.exists():
                    self.log.unlink()
                (self.release / "revocations-1.json").write_bytes(b'{"sequence":1}\n')
                (self.release / "revocations-1.sigstore.json").write_bytes(b"signed bundle\n")
                (self.release / name).write_bytes(b"different immutable bytes")
                result = self.run_step(runner)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(Path(runner) / "existing" / name), result.stdout)
                self.assertIn("differ", result.stdout)
                self.assertFalse(self.log.exists())
                self.assertEqual((self.release / name).read_bytes(), b"different immutable bytes")

    def test_all_dedicated_uploads_use_paths_not_label_aliases(self):
        # Includes prior-history alias restoration, not just final publication.
        for line in WORKFLOW.read_text().splitlines():
            self.assertNotIn("#revocations", line)
            self.assertNotIn("#$numbered", line)
