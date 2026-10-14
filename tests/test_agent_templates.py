import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_templates", ROOT / "scripts/validate-templates.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
AGENTS = ("claude", "codex", "goose", "opencode")


class AgentTemplates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("templates", "packs"):
            shutil.copytree(ROOT / directory, self.root / directory)
        shutil.copyfile(ROOT / "index.json", self.root / "index.json")
        self.template = self.root / "templates/agent-claude-runtime"

    def test_registry_payloads_are_complete(self):
        self.assertEqual(VALIDATOR.validate(self.root), 8)

    def test_missing_app_refused(self):
        (self.template / "app/check-runtime.sh").unlink()
        with self.assertRaisesRegex(ValueError, "missing or unsafe"):
            VALIDATOR.validate(self.root)

    def test_app_omitted_from_downloads_refused(self):
        path = self.template / "template.toml"
        path.write_text(path.read_text().replace('"app/check-runtime.sh", ', ""))
        with self.assertRaisesRegex(ValueError, "must be downloaded"):
            VALIDATOR.validate(self.root)

    def test_unsafe_paths_refused(self):
        for path in ("../outside", "/outside", r"app\outside"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe template path"):
                VALIDATOR.local_file(self.template, path)

    def test_symlink_payload_refused(self):
        path = self.template / "app/check-runtime.sh"
        path.unlink()
        path.symlink_to(self.template / "SETUP.md")
        with self.assertRaisesRegex(ValueError, "missing or unsafe"):
            VALIDATOR.validate(self.root)

    def test_unpinned_or_invalid_profile_refused(self):
        for ref in ("agent/claude", "agent/claude@latest", "../escape@1.0.0"):
            with self.subTest(ref=ref):
                (self.template / "policy/profile.toml").write_text(f'description = "test"\nextends = "{ref}"\n')
                with self.assertRaisesRegex(ValueError, "exact-version"):
                    VALIDATOR.validate(self.root)

    def test_duplicate_permissions_refused(self):
        path = self.template / "policy/profile.toml"
        path.write_text(path.read_text() + '\n[groups]\ninclude = ["github"]\n')
        with self.assertRaisesRegex(ValueError, "only describe and extend"):
            VALIDATOR.validate(self.root)

    def test_wrong_agent_profile_refused(self):
        path = self.template / "policy/profile.toml"
        path.write_text(path.read_text().replace("agent/claude@1.0.1", "agent/codex@1.0.0"))
        with self.assertRaisesRegex(ValueError, "wrong agent profile"):
            VALIDATOR.validate(self.root)

    def test_missing_pack_signature_refused(self):
        (self.root / "packs/agent/claude/1.0.1/manifest.sigstore.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing or unsafe"):
            VALIDATOR.validate(self.root)

    def test_tampered_pack_profile_refused(self):
        path = self.root / "packs/agent/claude/1.0.1/files/pack/profile.toml"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            VALIDATOR.validate(self.root)

    def test_index_metadata_mismatch_refused(self):
        path = self.root / "index.json"
        index = json.loads(path.read_text())
        index["templates"][0]["description"] = "Installed agent"
        path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, "metadata disagree"):
            VALIDATOR.validate(self.root)

    def test_runtime_checks_success_and_fail_closed(self):
        # Proves script behavior only, not the guest closure or client install.
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for runtime scaffold tests")
        for agent in AGENTS:
            script = ROOT / f"templates/agent-{agent}-runtime/app/check-runtime.sh"
            args = [node] + ([shutil.which("python3")] if agent != "codex" else [])
            with self.subTest(agent=agent):
                subprocess.run(["bash", "-n", str(script)], check=True)
                result = subprocess.run(["bash", str(script), *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("No agent client is installed", result.stdout)
                missing_args = subprocess.run(["bash", str(script)], capture_output=True)
                self.assertEqual(missing_args.returncode, 64)
                bad_binary = subprocess.run(["bash", str(script), "/nonexistent/runtime", *args[1:]], capture_output=True)
                self.assertNotEqual(bad_binary.returncode, 0)
                self.assertNotIn(b"Runtime check passed", bad_binary.stdout)

    def test_unsupported_service_form_refused(self):
        path = self.template / "flake.nix"
        path.write_text(path.read_text().replace("entrypoint.command", "services.agent.command"))
        with self.assertRaisesRegex(ValueError, "supported command entrypoint"):
            VALIDATOR.validate(self.root)

    def test_invented_secret_substitution_refused(self):
        path = self.template / "flake.nix"
        path.write_text(path.read_text() + '\n# ANTHROPIC_API_KEY = "$anthropic"\n')
        with self.assertRaisesRegex(ValueError, "invented secret"):
            VALIDATOR.validate(self.root)

    def test_unpinned_direct_nix_input_refused(self):
        path = self.template / "flake.nix"
        path.write_text(path.read_text().replace("b6018f87da91d19d0ab4cf979885689b469cdd41", "nixos-25.11"))
        with self.assertRaisesRegex(ValueError, "unpinned direct Nix input"):
            VALIDATOR.validate(self.root)
