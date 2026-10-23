"""Pure semantic controls; these fixtures are NOT cryptographic/native evidence."""

import base64
import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "consumer_session", ROOT / "scripts" / "check-python-consumer-session.py",
)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)
PLAN = "sha256:" + "a" * 64
ROOTFS = "b" * 64
DESCRIPTOR = "c" * 64
KEY = "d" * 64
REFERENCE = "runtime/python@1.1.0"


def fixture():
    def entry(event, labels=None):
        return {"tenant": "local", "plan_id": PLAN, "image_sha256": ROOTFS,
                "event": event, "labels": labels or {}}
    entries = [
        entry("plan.admitted"),
        entry("plan.asset_identities", {
            "asset_count": "1", "asset_0_kind": "registry_pack",
            "asset_0_name": REFERENCE, "asset_0_digest": DESCRIPTOR,
        }),
        entry("plan.launched", {"backend": "firecracker"}),
        entry("plan.exited", {"backend": "firecracker", "exit_code": "0", "captured": "true"}),
        entry("session.sealed"),
    ]
    report = {
        "tenant": "local", "plan_id": PLAN, "verdict": "VERIFIED", "late_entries": 0,
        "event_count": 4, "seals": [{"seq": 4, "seal": {
            "reason": "exited", "exit_code": "0", "image_sha256": ROOTFS, "event_count": 4,
        }}],
    }
    return report, entries


def receipt_fixture():
    return {
        "payload": {
            "schema_version": 1, "receipt_id": "unit", "recorded_at": "unit",
            "invocation": {
                "manifest": None, "image": None, "cpus": 1, "memory": "256M",
                "profile": "unit", "network_posture": "deny-all", "egress_enforcement": "unit",
                "command": {
                    "kind": "inline", "argv_len": len(check.COMMAND),
                    "argv_sha256": check.sha(json.dumps(
                        check.COMMAND, separators=(",", ":"),
                    ).encode()),
                },
                "env_keys": [], "mounts": [], "timeout_secs": 60,
            },
            "outcome": {
                "exit_code": 0, "success": True, "stdout_sha256": check.sha(check.OUTPUT),
                "stderr_sha256": check.sha(b""), "stdout_bytes": len(check.OUTPUT),
                "stderr_bytes": 0,
            },
        },
        "signature": {
            "algorithm": "ed25519", "signer_id": "unit", "public_key_sha256": KEY,
            "signature_base64": "unsigned-unit",
        },
    }


class ConsumerSessionTests(unittest.TestCase):
    def judge(self, report, entries):
        check.session_semantics(report, entries, PLAN, REFERENCE, DESCRIPTOR, ROOTFS)

    def test_expected_sealed_identity_semantics(self):
        self.judge(*fixture())

    def test_verdict_late_entries_and_coverage_refuse(self):
        for key, wrong in (("verdict", "UNSEALED"), ("verdict", "MISMATCH"),
                           ("late_entries", 1), ("event_count", 0), ("plan_id", "other")):
            with self.subTest(key=key, wrong=wrong):
                report, entries = fixture()
                report[key] = wrong
                with self.assertRaises(check.EvidenceError):
                    self.judge(report, entries)

    def test_missing_or_duplicate_lifecycle_events_refuse(self):
        for index in range(5):
            for duplicate in (False, True):
                with self.subTest(index=index, duplicate=duplicate):
                    report, entries = fixture()
                    if duplicate:
                        entries.insert(index, copy.deepcopy(entries[index]))
                    else:
                        entries.pop(index)
                    with self.assertRaises(check.EvidenceError):
                        self.judge(report, entries)

    def test_conflicting_pack_digest_and_identical_duplicate_refuse(self):
        for digest in (DESCRIPTOR, "e" * 64):
            report, entries = fixture()
            entries[1]["labels"].update({
                "asset_count": "2", "asset_1_kind": "registry_pack",
                "asset_1_name": REFERENCE, "asset_1_digest": digest,
            })
            with self.assertRaises(check.EvidenceError):
                self.judge(report, entries)

    def test_distinct_other_policy_asset_is_permitted(self):
        report, entries = fixture()
        entries[1]["labels"].update({
            "asset_count": "2", "asset_1_kind": "registry_pack",
            "asset_1_name": "agent/claude@1.0.1", "asset_1_digest": "e" * 64,
        })
        self.judge(report, entries)

    def test_failed_or_uncaptured_exit_and_wrong_backend_refuse(self):
        for key, value in (("exit_code", "1"), ("captured", "false"),
                           ("backend", "hvf")):
            report, entries = fixture()
            entries[3]["labels"][key] = value
            with self.assertRaises(check.EvidenceError):
                self.judge(report, entries)

    def test_wrong_or_failed_exit_seal_refuses(self):
        for key, value in (("reason", "failed"), ("exit_code", "1"),
                           ("image_sha256", "e" * 64), ("event_count", 0)):
            report, entries = fixture()
            report["seals"][0]["seal"][key] = value
            with self.assertRaises(check.EvidenceError):
                self.judge(report, entries)

    def test_wrong_image_and_failure_event_refuse(self):
        report, entries = fixture()
        entries[0]["image_sha256"] = "e" * 64
        with self.assertRaises(check.EvidenceError):
            self.judge(report, entries)
        report, entries = fixture()
        entries.insert(3, {"event": "plan.failed"})
        with self.assertRaises(check.EvidenceError):
            self.judge(report, entries)

    def test_canonical_snapshot_agreement_and_truncation(self):
        _, entries = fixture()
        entry = entries[0]
        envelope = {
            "entry": entry, "canonical": base64.urlsafe_b64encode(
                json.dumps(entry).encode(),
            ).decode().rstrip("="), "prev_hash": "not-a-real-proof", "signature": "unsigned-unit",
        }
        line = json.dumps(envelope).encode() + b"\n"
        self.assertEqual(check.session_entries(line, PLAN), [entry])
        with self.assertRaises(check.EvidenceError):
            check.session_entries(line[:-1], PLAN)
        envelope["entry"] = {**entry, "image_sha256": "e" * 64}
        with self.assertRaises(check.EvidenceError):
            check.session_entries(json.dumps(envelope).encode() + b"\n", PLAN)

    def test_duplicate_json_and_unsigned_extension_refuse(self):
        with self.assertRaises(check.EvidenceError):
            check.document(b'{"verdict":"VERIFIED","verdict":"MISMATCH"}')
        with self.assertRaises(check.EvidenceError):
            check.fields({"payload": {}, "signature": {}, "cleanup": True},
                         ("payload", "signature"))

    def test_receipt_expected_semantics_not_signature_proof(self):
        check.receipt_semantics(receipt_fixture(), KEY)

    def test_receipt_output_status_key_and_command_refusals(self):
        mutations = [
            ("outcome", "exit_code", 1), ("outcome", "success", False),
            ("outcome", "success", 1), ("outcome", "exit_code", False),
            ("outcome", "stdout_sha256", check.sha(b"wrong\n")),
            ("outcome", "stderr_bytes", 1),
            ("invocation", "command", {"kind": "launch_plan", "path_sha256": "e" * 64}),
            ("invocation", "env_keys", ["TOKEN"]),
            ("invocation", "mounts", [{"guest_path": "/host"}]),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key, value=value):
                receipt = receipt_fixture()
                receipt["payload"][section][key] = value
                with self.assertRaises(check.EvidenceError):
                    check.receipt_semantics(receipt, KEY)
        with self.assertRaises(check.EvidenceError):
            check.receipt_semantics(receipt_fixture(), "e" * 64)

    def test_receipt_unknown_fields_are_not_signed_authority(self):
        for location in ("payload", "signature", "invocation", "outcome"):
            with self.subTest(location=location):
                receipt = receipt_fixture()
                target = receipt[location] if location in receipt else receipt["payload"][location]
                target["cleanup"] = True
                with self.assertRaises(check.EvidenceError):
                    check.receipt_semantics(receipt, KEY)

    def test_non_json_constants_refuse(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.assertRaises(check.EvidenceError):
                check.document(constant)

    def test_verifier_command_is_not_replaced_with_a_success_boolean(self):
        # This is a process-boundary control, not a real signature verification.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            argv = ["trust", "audit", "verify", PLAN, "--tenant", "local", "--json"]
            environment = {"PATH": "/usr/bin:/bin", "MVM_HOME": "/unit-private"}
            with patch.object(check.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0)
                self.assertEqual(
                    check.run_verifier(Path("/unit-client"), argv, environment, output, "audit"),
                    b"",
                )
                call = run.call_args
                self.assertEqual(call.args, (["/unit-client", *argv],))
                self.assertEqual(call.kwargs["env"], environment)
                self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(call.kwargs["timeout"], 120)
                self.assertFalse(call.kwargs["check"])
                self.assertEqual((output / "audit.status").read_text(), "0\n")

    def test_crash_usage_and_signature_failure_statuses_refuse(self):
        for status in (-11, 1, 2, 101):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                with patch.object(check.subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], status)
                    with self.assertRaises(check.EvidenceError):
                        check.run_verifier(
                            Path("/unit-client"), ["trust", "receipt", "verify", "unit"],
                            {}, Path(temporary), "receipt",
                        )
                    self.assertEqual(
                        (Path(temporary) / "receipt.status").read_text(), f"{status}\n",
                    )

    def test_existing_verifier_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "audit.stdout").write_bytes(b"old result")
            with patch.object(check.subprocess, "run") as run:
                with self.assertRaises(FileExistsError):
                    check.run_verifier(Path("/unit-client"), [], {}, output, "audit")
                run.assert_not_called()
            self.assertEqual((output / "audit.stdout").read_bytes(), b"old result")

    def test_linked_oversized_and_nonregular_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular"
            regular.write_bytes(b"input")
            linked = root / "linked"
            linked.symlink_to(regular)
            for path, bound in ((linked, 10), (regular, 4), (root, 10)):
                with self.subTest(path=path, bound=bound):
                    with self.assertRaises((OSError, check.EvidenceError)):
                        check.read_regular(path, bound)


if __name__ == "__main__":
    unittest.main()
