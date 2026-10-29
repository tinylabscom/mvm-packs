"""Unit checkout-boundary evidence, not authenticated GitHub workflow proof."""

import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/protected-observer-source.py"
SPEC = importlib.util.spec_from_file_location("protected_source", SCRIPT)
loader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loader)


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


class ProtectedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root_patch = patch.object(loader, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.git("init", "-q")
        self.git("config", "user.name", "Source unit test")
        self.git("config", "user.email", "unit@example.invalid")
        self.doc = {
            "schema_version": 2,
            "role": "protected-observer",
            "backend": "diagnostic",
            "version": 1,
        }
        self.write(loader.v2.POLICY_PATH, encode(self.doc))
        self.entry = {
            "path": loader.v2.POLICY_PATH,
            "role": "protected-observer",
            "backend": "diagnostic",
            "version": 1,
            "document": loader.v2.digest(encode(self.doc)),
        }
        self.registry = {"schema_version": 2, "policies": [self.entry]}
        self.write(loader.REGISTRY_PATH, encode(self.registry))
        self.write(loader.WORKFLOW_PATH, b"name: unit fixture only\n")
        self.write(".gitignore", b"__pycache__/\n")
        self.commit()

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def write(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    def commit(self):
        self.git("add", "-A")
        self.git(
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-qm",
            "unit fixture",
        )
        sha = self.git("rev-parse", "HEAD").decode().strip()
        self.env = {
            "GITHUB_REPOSITORY": "tinylabscom/mvm-packs",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": sha,
            "GITHUB_WORKFLOW_SHA": sha,
            "GITHUB_WORKFLOW_REF": "tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
        }

    def load(self):
        return loader.load_source(self.env)

    def test_contract_and_existing_resolver(self):
        result = self.load()
        self.assertEqual(
            set(result),
            {
                "source",
                "checkout_sha",
                "workflow_sha",
                "trusted_registry",
                "trusted_policies",
            },
        )
        self.assertEqual(result["checkout_sha"], self.env["GITHUB_SHA"])
        self.assertEqual(result["workflow_sha"], self.env["GITHUB_WORKFLOW_SHA"])
        self.assertEqual(result["trusted_registry"], encode(self.registry))
        binding = {
            **self.entry,
            "source": result["source"],
            "registry": loader.v2.digest(result["trusted_registry"]),
        }
        self.assertEqual(
            loader.v2.resolve_policy(
                binding,
                result["trusted_policies"],
                source=result["source"],
                trusted_registry=result["trusted_registry"],
            ),
            self.doc,
        )

    def test_source_ref_workflow_and_sha_mismatches(self):
        for field, value in (
            ("GITHUB_REPOSITORY", "attacker/mvm-packs"),
            ("GITHUB_REF", "refs/heads/feature"),
            (
                "GITHUB_WORKFLOW_REF",
                self.env["GITHUB_WORKFLOW_REF"].replace("publish", "other"),
            ),
            ("GITHUB_WORKFLOW_SHA", ""),
            ("GITHUB_WORKFLOW_SHA", "a" * 39),
            ("GITHUB_WORKFLOW_SHA", "A" * 40),
            ("GITHUB_WORKFLOW_SHA", "a" * 40),
            ("GITHUB_SHA", "b" * 40),
        ):
            with (
                self.subTest(field=field, value=value),
                patch.dict(self.env, {field: value}),
            ):
                with self.assertRaises(loader.WitnessError):
                    self.load()
        self.env.pop("GITHUB_WORKFLOW_SHA")
        with self.assertRaises(loader.WitnessError):
            self.load()

    def test_actual_head_and_toplevel_required(self):
        self.env.update(GITHUB_SHA="a" * 40, GITHUB_WORKFLOW_SHA="a" * 40)
        with self.assertRaises(loader.WitnessError):
            self.load()
        nested = self.root / "nested"
        nested.mkdir()
        with patch.object(loader, "ROOT", nested):
            with self.assertRaises(loader.WitnessError):
                self.load()

    def test_dirty_tracked_untracked_and_staged_refuse(self):
        path = self.root / loader.WORKFLOW_PATH
        raw = path.read_bytes()
        path.write_bytes(b"local override\n")
        with self.assertRaises(loader.WitnessError):
            self.load()
        self.git("add", loader.WORKFLOW_PATH)
        with self.assertRaises(loader.WitnessError):
            self.load()
        path.write_bytes(raw)
        self.git("add", loader.WORKFLOW_PATH)
        self.write("author-policy.json", b"{}")
        with self.assertRaises(loader.WitnessError):
            self.load()

    def test_ignored_artifacts_allowed_and_git_routing_not_accepted(self):
        self.write("__pycache__/unit.pyc", b"ignored")
        with patch.dict(os.environ, {"GIT_DIR": "/nonexistent", "GIT_WORK_TREE": "/"}):
            self.load()

    def test_exact_head_bytes_even_if_index_hides_changes(self):
        for path in (loader.WORKFLOW_PATH, loader.REGISTRY_PATH, loader.v2.POLICY_PATH):
            with self.subTest(path=path):
                target = self.root / path
                raw = target.read_bytes()
                self.git("update-index", "--assume-unchanged", path)
                target.write_bytes(raw + b" ")
                with self.assertRaises(loader.WitnessError):
                    self.load()
                target.write_bytes(raw)
                self.git("update-index", "--no-assume-unchanged", path)

    def test_missing_fixed_files_refuse_even_when_absence_committed(self):
        for path in (loader.WORKFLOW_PATH, loader.REGISTRY_PATH, loader.v2.POLICY_PATH):
            with self.subTest(path=path):
                target = self.root / path
                raw = target.read_bytes()
                target.unlink()
                self.commit()
                with self.assertRaises(loader.WitnessError):
                    self.load()
                target.write_bytes(raw)
                self.commit()

    def test_registry_and_document_fail_closed(self):
        variants = [
            (loader.REGISTRY_PATH, b"not JSON"),
            (
                loader.REGISTRY_PATH,
                b'{"schema_version":2,"schema_version":2,"policies":[]}',
            ),
            (loader.REGISTRY_PATH, encode({**self.registry, "schema_version": True})),
            (loader.REGISTRY_PATH, encode({**self.registry, "policies": []})),
            (
                loader.REGISTRY_PATH,
                encode({**self.registry, "policies": [self.entry] * 2}),
            ),
            (
                loader.REGISTRY_PATH,
                encode(
                    {
                        **self.registry,
                        "policies": [{**self.entry, "path": "author.json"}],
                    }
                ),
            ),
            (
                loader.REGISTRY_PATH,
                encode(
                    {
                        **self.registry,
                        "policies": [
                            {
                                **self.entry,
                                "document": {
                                    "sha256": "0" * 64,
                                    "size": len(encode(self.doc)),
                                },
                            }
                        ],
                    }
                ),
            ),
            (loader.v2.POLICY_PATH, b"not JSON"),
            (loader.v2.POLICY_PATH, b'{"schema_version":2,"schema_version":2}'),
            (loader.v2.POLICY_PATH, encode({**self.doc, "runtime_accept": True})),
            (loader.v2.POLICY_PATH, encode({**self.doc, "version": []})),
        ]
        for path, raw in variants:
            with self.subTest(path=path, raw=raw):
                original = (self.root / path).read_bytes()
                self.write(path, raw)
                self.commit()
                with self.assertRaises(loader.WitnessError):
                    self.load()
                self.write(path, original)
                self.commit()

    def test_fixed_files_links_and_bounds_refuse(self):
        for path in (loader.WORKFLOW_PATH, loader.REGISTRY_PATH, loader.v2.POLICY_PATH):
            target = self.root / path
            raw = target.read_bytes()
            other = self.root / "__pycache__" / "linked"
            self.write("__pycache__/linked", raw)
            for kind in ("symlink", "hardlink", "empty", "oversize"):
                with self.subTest(path=path, kind=kind):
                    target.unlink()
                    if kind == "symlink":
                        target.symlink_to(other)
                    elif kind == "hardlink":
                        os.link(other, target)
                    else:
                        target.write_bytes(
                            b"" if kind == "empty" else b"x" * (loader.v2.LIMIT + 1)
                        )
                    self.commit()
                    with self.assertRaises(loader.WitnessError):
                        self.load()
                    target.unlink()
                    target.write_bytes(raw)
                    self.commit()

    def test_no_caller_selected_root_path_or_bytes(self):
        self.assertEqual(
            list(inspect.signature(loader.load_source).parameters), ["environment"]
        )
        with self.assertRaises(TypeError):
            loader.load_source(self.env, root=self.root)
        # Extra author hints do not change the fixed selections.
        self.env.update(POLICY_PATH="author.json", TRUSTED_REGISTRY="{}")
        self.assertEqual(self.load()["trusted_registry"], encode(self.registry))


if __name__ == "__main__":
    unittest.main()
