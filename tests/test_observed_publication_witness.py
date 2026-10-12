"""Unit-only witness contract fixtures; no client, VM or real signing is run."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_sign_composed_image as signing_fixtures


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "observed-publication-witness.py"
spec = importlib.util.spec_from_file_location("observed_publication_witness", SCRIPT)
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(
            tempfile, "tempdir", str(Path(tempfile.gettempdir()).resolve())))
        self.fixture = signing_fixtures.SigningTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        with mock.patch.object(signing_fixtures.signer, "sign_and_verify",
                               side_effect=self.fixture.fake_sign):
            self.fixture.prepare()
        self.root = self.fixture.root
        self.directory = self.root / "witness"
        self.directory.mkdir()
        # Explicit mock backend/policy; not a claim about any supported runtime.
        self.policy = {
            "schema_version": 1, "backend": "unit-mock", "version": 1,
            "checks": {mode: {
                "unit_measured_exit": {"applicability": "required",
                                       "value_type": "integer", "expected": 0},
                "unit_measured_lifecycle": {"applicability": "required",
                    "value_type": "string", "expected": mode + "-unit-observation"},
                "unit_inapplicable": {"applicability": "inapplicable"},
            } for mode in witness.MODES},
        }
        self.client_files = {}
        for role in witness.CLIENT_ROLES:
            path = self.root / ("client-" + role)
            path.write_bytes(("UNIT-MOCK-NOT-A-RELEASED-CLIENT:" + role).encode())
            self.client_files[role] = path
        self.report = {
            "schema_version": 1, "kind": "observed-publication-witness",
            "source": witness.source_identity(self.fixture.environment),
            "reference": "runtime/python@1.1.0",
            "descriptor": witness.digest((self.fixture.output / "image-descriptor.json").read_bytes()),
            "signed_image_evidence": {
                name: witness.digest((self.fixture.output / name).read_bytes())
                for name in witness.stager.EVIDENCE_NAMES},
            "images_lock": witness.digest(self.fixture.images_lock.read_bytes()),
            "base_set": self.fixture.base,
            "client": {"repository": "tinylabscom/mvm", "tag": "v0.0.1",
                       "architecture": "aarch64", **{
                role: witness.digest(path.read_bytes()) for role, path in self.client_files.items()}},
            "policy": {}, "modes": {},
        }
        self.install_policy()
        for mode in witness.MODES:
            self.report["modes"][mode] = {
                "transcript": {}, "commands": [],
                "observations": {
                    "unit_measured_exit": {"command_index": 0, "state": "observed", "value": 0},
                    "unit_measured_lifecycle": {"command_index": 0, "state": "observed",
                                                "value": mode + "-unit-observation"},
                    "unit_inapplicable": {"command_index": 0, "state": "not-applicable", "value": None},
                },
            }
        self.write_raw()
        self.write_report()

    def install_policy(self):
        raw = encode(self.policy)
        binding = {"backend": self.policy["backend"], "version": self.policy["version"],
                   "sha256": witness.digest(raw)["sha256"]}
        self.report["policy"] = binding
        self.trusted_policies = {(binding["backend"], binding["version"], binding["sha256"]): raw}

    def binding(self, mode):
        return {"schema_version": 1, "mode": mode, **{
            field: self.report[field] for field in ("source", "descriptor", "client", "policy")}}

    def write_raw(self):
        for mode in witness.MODES:
            observations = {name: {"state": value["state"], "value": value["value"]}
                            for name, value in self.report["modes"][mode]["observations"].items()}
            stdout = encode({**self.binding(mode), "observations": observations})
            (self.directory / f"{mode}-0.stdout").write_bytes(stdout)
            (self.directory / f"{mode}-0.stderr").write_bytes(b"")
            commands = [{
                "argv": ["unit-mock-observer", "--mode", mode],
                "exit_code": 0, "stdout": witness.digest(stdout), "stderr": witness.digest(b""),
            }]
            self.report["modes"][mode]["commands"] = commands
            raw = encode({**self.binding(mode), "commands": commands})
            (self.directory / f"{mode}.json").write_bytes(raw)
            self.report["modes"][mode]["transcript"] = witness.digest(raw)

    def write_report(self):
        (self.directory / "witness.json").write_bytes(encode(self.report))
        (self.directory / "witness.sigstore.json").write_bytes(b"UNIT-MOCK-SIGNATURE")

    def verify(self, **overrides):
        arguments = {
            "directory": self.directory, "evidence": self.fixture.output,
            "reference": self.report["reference"], "pack_source": self.fixture.pack_source,
            "images_lock": self.fixture.images_lock, "client_files": self.client_files,
            "environment": self.fixture.environment, "trusted_policies": self.trusted_policies,
        }
        arguments.update(overrides)
        # All cryptographic verifications mocked; content/stager logic is real.
        with mock.patch.object(witness.stager, "verify_bundle") as image_signature, \
                mock.patch.object(witness, "verify_report_signature") as report_signature:
            result = witness.verify(**arguments)
            self.assertEqual(image_signature.call_count, 3)
            report_signature.assert_called_once()
            return result

    def test_mock_signed_bytes_and_raw_contract_roundtrip(self):
        self.assertEqual(self.verify(), self.report)

    def test_missing_unknown_fields_versions_modes_and_checks_refused(self):
        variants = []
        for field in witness.REPORT_FIELDS:
            value = copy.deepcopy(self.report)
            del value[field]
            variants.append(value)
        for schema in (True, 2, "1"):
            value = copy.deepcopy(self.report)
            value["schema_version"] = schema
            variants.append(value)
        for mode in witness.MODES:
            value = copy.deepcopy(self.report)
            del value["modes"][mode]
            variants.append(value)
            for change in ("missing", "unknown", "failed", "boolean", "float", "na", "default"):
                value = copy.deepcopy(self.report)
                observed = value["modes"][mode]["observations"]
                if change == "missing":
                    del observed["unit_measured_exit"]
                elif change == "unknown":
                    observed["author_success"] = {"command_index": 0, "value": True, "state": "observed"}
                else:
                    observed["unit_measured_exit"]["value"] = {
                        "failed": 1, "boolean": False, "float": 0.0, "na": None, "default": 0,
                    }[change]
                    if change == "na":
                        observed["unit_measured_exit"]["state"] = "not-applicable"
                    if change == "default":
                        del observed["unit_measured_exit"]["state"]
                variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(witness.WitnessError):
                witness.validate_report(value, self.trusted_policies)

    def test_unknown_backend_policy_version_digest_refused(self):
        for key, replacement in (("backend", "other"), ("version", 2), ("sha256", "d" * 64)):
            value = copy.deepcopy(self.report)
            value["policy"][key] = replacement
            with self.subTest(key=key), self.assertRaises(witness.WitnessError):
                witness.validate_report(value, self.trusted_policies)

    def test_policy_requires_nonempty_applicable_checks_in_both_modes(self):
        for bad in ({}, {"unit_na": {"applicability": "inapplicable"}}):
            self.policy["checks"]["persistent"] = bad
            self.install_policy()
            with self.assertRaises(witness.WitnessError):
                witness.validate_report(self.report, self.trusted_policies)

    def test_no_author_boolean_policy_verdict(self):
        self.policy["checks"]["transient"]["unit_measured_exit"]["expected"] = True
        self.install_policy()
        with self.assertRaises(witness.WitnessError):
            witness.validate_report(self.report, self.trusted_policies)

    def test_policy_bytes_hash_is_verified(self):
        key = next(iter(self.trusted_policies))
        self.trusted_policies[key] += b" "
        with self.assertRaises(witness.WitnessError):
            witness.validate_report(self.report, self.trusted_policies)

    def test_all_actual_commands_must_succeed(self):
        for code in (1, -9, True, None):
            value = copy.deepcopy(self.report)
            value["modes"]["persistent"]["commands"][0]["exit_code"] = code
            with self.subTest(code=code), self.assertRaises(witness.WitnessError):
                witness.validate_report(value, self.trusted_policies)

    def test_replay_source_run_attempt_and_reference_refused(self):
        for key, value in (("GITHUB_SHA", "d" * 40), ("GITHUB_RUN_ID", "1235"),
                           ("GITHUB_RUN_ATTEMPT", "3"), ("GITHUB_REF", "refs/heads/author")):
            environment = {**self.fixture.environment, key: value}
            with self.subTest(key=key), self.assertRaises(witness.WitnessError):
                self.verify(environment=environment)
        with self.assertRaises(witness.WitnessError):
            self.verify(reference="runtime/python@1.1.1")

    def test_every_signed_evidence_byte_is_bound(self):
        for name in witness.stager.EVIDENCE_NAMES:
            path = self.fixture.output / name
            original = path.read_bytes()
            path.write_bytes(original + b"tampered")
            with self.subTest(name=name), self.assertRaises(witness.WitnessError):
                self.verify()
            path.write_bytes(original)

    def test_every_client_input_and_lock_is_bound(self):
        for path in (*self.client_files.values(), self.fixture.images_lock):
            original = path.read_bytes()
            path.write_bytes(original + b"tampered")
            with self.subTest(path=path), self.assertRaises(witness.WitnessError):
                self.verify()
            path.write_bytes(original)

    def test_client_architecture_must_match_candidate_platform(self):
        self.report["client"]["architecture"] = "x86_64"
        self.write_raw()
        self.write_report()
        with self.assertRaises(witness.WitnessError):
            self.verify()

    def test_rehashed_resigned_old_provenance_run_cannot_supply_current_witness(self):
        path = self.fixture.output / "provenance.json"
        provenance = json.loads(path.read_bytes())
        provenance["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/tinylabscom/mvm-packs/actions/runs/1234/attempts/1")
        path.write_bytes(encode(provenance))
        self.fixture.fake_sign(path, self.fixture.output / "provenance.signature.json")
        # Rehash the otherwise legitimate evidence envelope so only the
        # independently expected current source/run/attempt check catches replay.
        envelope_path = self.fixture.output / "image-evidence.json"
        envelope = json.loads(envelope_path.read_bytes())
        for name in ("provenance.json", "provenance.signature.json"):
            envelope["assets"][name] = witness.digest((self.fixture.output / name).read_bytes())
        envelope_path.write_bytes(encode(envelope))
        self.fixture.fake_sign(envelope_path, self.fixture.output / "image-evidence.sigstore.json")
        self.report["signed_image_evidence"] = {
            name: witness.digest((self.fixture.output / name).read_bytes())
            for name in witness.stager.EVIDENCE_NAMES}
        self.write_report()
        with self.assertRaises(witness.WitnessError):
            self.verify()

    def test_raw_hash_and_semantic_bindings_refuse_even_rehashed_tampering(self):
        for field in ("source", "descriptor", "client", "policy", "mode"):
            mode = "transient"
            path = self.directory / f"{mode}.json"
            raw = json.loads(path.read_bytes())
            raw[field] = "wrong"
            path.write_bytes(encode(raw))
            self.report["modes"][mode]["transcript"] = witness.digest(path.read_bytes())
            self.write_report()
            with self.subTest(field=field), self.assertRaises(witness.WitnessError):
                self.verify()
            self.write_raw()
        path = self.directory / "persistent-0.stdout"
        path.write_bytes(path.read_bytes() + b"tampered")
        with self.assertRaises(witness.WitnessError):
            self.verify()

    def test_report_cannot_replace_raw_observation_with_signed_claim(self):
        path = self.directory / "transient-0.stdout"
        raw = json.loads(path.read_bytes())
        raw["observations"]["unit_measured_exit"]["value"] = False
        path.write_bytes(encode(raw))
        self.report["modes"]["transient"]["commands"][0]["stdout"] = witness.digest(path.read_bytes())
        transcript = {**self.binding("transient"), "commands": self.report["modes"]["transient"]["commands"]}
        raw = encode(transcript)
        (self.directory / "transient.json").write_bytes(raw)
        self.report["modes"]["transient"]["transcript"] = witness.digest(raw)
        self.write_report()
        with self.assertRaises(witness.WitnessError):
            self.verify()

    def test_unknown_files_symlinks_hardlinks_and_resource_bounds(self):
        path = self.directory / "extra"
        path.write_bytes(b"x")
        with self.assertRaises(witness.WitnessError):
            self.verify()
        path.unlink()
        original = self.directory / "transient-0.stdout"
        backup = self.root / "backup"
        original.rename(backup)
        original.symlink_to(backup)
        with self.assertRaises(witness.WitnessError):
            self.verify()
        original.unlink()
        os.link(backup, original)
        with self.assertRaises(witness.WitnessError):
            self.verify()
        with self.assertRaises(witness.WitnessError):
            witness.bounded_bytes(backup, limit=1)
        with self.assertRaises(witness.stager.binder.CandidateError):
            witness.stager.binder.copy_regular(backup, self.root / "bounded-copy", max_bytes=1)

    def test_duplicate_keys_nonfinite_and_malformed_json_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"not json"):
            with self.subTest(raw=raw), self.assertRaises(witness.WitnessError):
                witness.parse_json(raw)

    def test_fifo_replacement_before_open_is_nonblocking_and_refused(self):
        original_open = os.open
        for reader in ("bounded", "copier"):
            path = self.root / ("race-" + reader)
            path.write_bytes(b"regular-before-open")
            target = self.root / ("race-copy-" + reader)
            def replace_before_open(source, flags, *args, **kwargs):
                if Path(source) == path:
                    # Assert before replacing: a regression fails without
                    # actually entering a blocking FIFO open in this test.
                    self.assertTrue(flags & os.O_NONBLOCK)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    path.unlink()
                    os.mkfifo(path)
                return original_open(source, flags, *args, **kwargs)
            with self.subTest(reader=reader), mock.patch.object(os, "open", side_effect=replace_before_open):
                if reader == "bounded":
                    with self.assertRaises(witness.WitnessError):
                        witness.bounded_bytes(path)
                else:
                    with self.assertRaises(witness.stager.binder.CandidateError):
                        witness.stager.binder.copy_regular(path, target)
            self.assertFalse(target.exists())

    def test_required_nonblocking_nofollow_flags_fail_closed(self):
        path = self.root / "flag-input"
        path.write_bytes(b"input")
        for flag in ("O_NONBLOCK", "O_NOFOLLOW"):
            with self.subTest(flag=flag), mock.patch.object(os, flag, None):
                with self.assertRaises(witness.WitnessError):
                    witness.bounded_bytes(path)
                with self.assertRaises(witness.stager.binder.CandidateError):
                    witness.stager.binder.copy_regular(path, self.root / "flag-output")

    def test_real_fifo_evidence_and_client_slots_refuse_without_writer(self):
        for slot in ("evidence", "client"):
            path = (self.fixture.output / "rootfs.ext4" if slot == "evidence"
                    else self.client_files["archive"])
            path.unlink()
            os.mkfifo(path)
            code = """
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("fifo_witness", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.stager.binder.copy_regular(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
except module.stager.binder.CandidateError:
    sys.exit(0)
sys.exit(1)
"""
            result = subprocess.run(
                [sys.executable, "-c", code, str(SCRIPT), str(path),
                 str(self.root / ("fifo-target-" + slot))],
                capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_signature_uses_current_oidc_and_exact_source_extensions(self):
        with mock.patch.object(witness.subprocess, "run") as run:
            witness.verify_report_signature(Path("blob"), Path("bundle"), self.report["source"])
        command = run.call_args.args[0]
        for option, expected in (
            ("--certificate-identity", witness.signer.PUBLISHER_IDENTITY),
            ("--certificate-oidc-issuer", witness.signer.PUBLISHER_ISSUER),
            ("--certificate-github-workflow-repository", "tinylabscom/mvm-packs"),
            ("--certificate-github-workflow-ref", "refs/heads/main"),
            ("--certificate-github-workflow-sha", self.fixture.environment["GITHUB_SHA"]),
        ):
            self.assertEqual(command[command.index(option) + 1], expected)
        self.assertNotIn(witness.signer.publisher.FORMER_IDENTITY, command)
        for error in (OSError("missing cosign"), subprocess.CalledProcessError(1, "cosign"),
                      subprocess.TimeoutExpired("cosign", 300)):
            with mock.patch.object(witness.subprocess, "run", side_effect=error), \
                    self.assertRaises(witness.WitnessError):
                witness.verify_report_signature(Path("blob"), Path("bundle"), self.report["source"])

    def test_signature_failure_propagates_and_no_producer_or_signer_api_exists(self):
        with mock.patch.object(witness.stager, "verify_bundle"), \
                mock.patch.object(witness, "verify_report_signature",
                                  side_effect=witness.WitnessError("invalid signature")), \
                self.assertRaises(witness.WitnessError):
            witness.verify(
                directory=self.directory, evidence=self.fixture.output,
                reference=self.report["reference"], pack_source=self.fixture.pack_source,
                images_lock=self.fixture.images_lock, client_files=self.client_files,
                environment=self.fixture.environment, trusted_policies=self.trusted_policies)
        self.assertFalse(hasattr(witness, "produce"))
        self.assertFalse(hasattr(witness, "sign"))


if __name__ == "__main__":
    unittest.main()
