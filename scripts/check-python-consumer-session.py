#!/usr/bin/env python3
"""Verify the signed output and sealed lifecycle of an already-finished probe.

This does not pull, boot, stop, publish, or authenticate a release. The enclosing
clean-consumer runner must establish those inputs and the exclusive private
MVM_HOME. Cryptography is delegated to the pinned client's existing verifiers;
the checks here add expected-output, pack-identity and lifecycle semantics.
The resulting unsigned report is component evidence, not a protected observer
receipt, an off-host audit anchor, or proof of original native Child custody.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path


MAX_INPUT = 2 * 1024 * 1024
OUTPUT = b"PS06-PYTHON-OK\n"
COMMAND = [
    "/bin/python3", "-c",
    "import os,sys; assert sys.version_info[:2] == (3,12); "
    "assert set(os.listdir('/sys/class/net')) == {'lo'}; print('PS06-PYTHON-OK')",
]


class EvidenceError(ValueError):
    """A required input, signature check, or semantic binding did not hold."""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def document(data):
    def invalid_constant(value):
        raise EvidenceError(f"non-JSON numeric constant: {value}")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


def fields(value, required, optional=()):
    require(isinstance(value, dict), "expected a JSON object")
    require(set(required) <= value.keys() <= set(required) | set(optional),
            "missing or unknown JSON fields")


def read_regular(path, maximum=MAX_INPUT):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                f"{path.name} is not a single-link regular-file input")
        require(info.st_size <= maximum, f"{path.name} exceeds its bound")
        data = stream.read(maximum + 1)
        require(len(data) == info.st_size, f"{path.name} changed or exceeds its bound")
        return data, (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))


def receipt_semantics(receipt, public_key_sha256):
    """Check only semantics; callers MUST also run the canonical verifier."""
    fields(receipt, ("payload", "signature"))
    payload, signature = receipt["payload"], receipt["signature"]
    fields(payload, ("schema_version", "receipt_id", "recorded_at", "invocation", "outcome"))
    fields(signature, ("algorithm", "signer_id", "public_key_sha256", "signature_base64"))
    require(type(payload["schema_version"]) is int and payload["schema_version"] == 1
            and signature["algorithm"] == "ed25519",
            "unsupported receipt schema/signature")
    require(signature["public_key_sha256"] == public_key_sha256, "wrong setup audit key")
    invocation = payload["invocation"]
    fields(invocation, (
        "manifest", "image", "cpus", "memory", "profile", "network_posture",
        "egress_enforcement", "command", "env_keys", "mounts", "timeout_secs",
    ), ("ai_token_budget",))
    # Fail on unsigned extensions: the production serde verifier ignores unknown
    # receipt fields. In particular a supplied "cleanup": true is not evidence.
    expected_command = {
        "kind": "inline", "argv_len": len(COMMAND),
        "argv_sha256": sha(json.dumps(COMMAND, separators=(",", ":")).encode()),
    }
    require(invocation["command"] == expected_command
            and type(invocation["command"].get("argv_len")) is int, "wrong probe argv")
    require(invocation["env_keys"] == [] and invocation["mounts"] == [],
            "probe inherited environment or mounts")
    require(invocation.get("ai_token_budget") is None, "unexpected AI authority")
    expected_outcome = {
        "exit_code": 0, "success": True,
        "stdout_sha256": sha(OUTPUT), "stderr_sha256": sha(b""),
        "stdout_bytes": len(OUTPUT), "stderr_bytes": 0,
    }
    outcome = payload["outcome"]
    require(outcome == expected_outcome
            and type(outcome.get("success")) is bool
            and all(type(outcome.get(key)) is int
                    for key in ("exit_code", "stdout_bytes", "stderr_bytes")),
            "wrong guest output or exit")


def session_entries(chain, plan_id):
    require(chain.endswith(b"\n"), "truncated audit chain")
    selected = []
    for line in chain.splitlines():
        envelope = document(line)
        fields(envelope, ("entry", "canonical", "prev_hash", "signature"))
        canonical = envelope["canonical"]
        require(isinstance(canonical, str), "missing canonical signed bytes")
        signed = document(base64.b64decode(
            canonical + "=" * (-len(canonical) % 4), altchars=b"-_", validate=True,
        ))
        require(isinstance(signed, dict), "signed audit entry must be an object")
        require(signed == envelope["entry"], "readable entry differs from signed bytes")
        if signed.get("plan_id") == plan_id:
            require(signed.get("tenant") == "local", "wrong session tenant")
            selected.append(signed)
    require(selected, "missing plan session")
    return selected


def session_semantics(report, entries, plan_id, reference, descriptor_sha256, rootfs_sha256):
    """Add identity/teardown requirements to the canonical session verdict."""
    require(report.get("tenant") == "local" and report.get("plan_id") == plan_id,
            "wrong verified session")
    require(report.get("verdict") == "VERIFIED"
            and type(report.get("late_entries")) is int and report["late_entries"] == 0,
            "session is not verified and fully sealed")
    events = [entry["event"] for entry in entries]
    require(events[0] == "plan.admitted" and events[-1] == "session.sealed",
            "missing admission or final seal")
    for event in ("plan.admitted", "plan.asset_identities", "plan.launched", "plan.exited",
                  "session.sealed"):
        require(events.count(event) == 1, f"missing or duplicate {event}")
    require(not any(event in events for event in (
        "plan.failed", "plan.wall_clock_expired", "verb_denied",
    )), "session includes a failure")
    require(events.index("plan.launched") < events.index("plan.exited"),
            "exit precedes launch")
    require(all(entry.get("image_sha256") == rootfs_sha256 for entry in entries),
            "session image differs from expected rootfs")
    assets = next(entry["labels"] for entry in entries if entry["event"] == "plan.asset_identities")
    count = assets.get("asset_count", "")
    require(re.fullmatch(r"[1-9][0-9]{0,2}", count) is not None, "invalid asset count")
    matching = [
        assets.get(f"asset_{i}_digest") for i in range(int(count))
        if assets.get(f"asset_{i}_kind") == "registry_pack"
        and assets.get(f"asset_{i}_name") == reference
    ]
    require(matching == [descriptor_sha256], "ambiguous or wrong authenticated pack identity")
    exited = next(entry["labels"] for entry in entries if entry["event"] == "plan.exited")
    require(exited.get("exit_code") == "0" and exited.get("captured") == "true",
            "workload exit was not captured successfully")
    launched = next(entry["labels"] for entry in entries if entry["event"] == "plan.launched")
    require(exited.get("backend") == launched.get("backend") and bool(exited.get("backend")),
            "launch/exit backend disagreement")
    seals = report.get("seals", [])
    require(len(seals) == 1 and type(report.get("event_count")) is int
            and report["event_count"] == len(entries) - 1,
            "session coverage/count mismatch")
    seal = seals[0]["seal"]
    require(seal.get("reason") == "exited" and seal.get("exit_code") == "0"
            and seal.get("image_sha256") == rootfs_sha256
            and seal.get("event_count") == len(entries) - 1,
            "session lacks a matching successful exit seal")


def run_verifier(client, args, environment, output, name):
    """Retain actual status/streams; no boolean signature-success input exists."""
    with (output / f"{name}.stdout").open("xb") as stdout:
        with (output / f"{name}.stderr").open("xb") as stderr:
            result = subprocess.run(
                [str(client), *args], env=environment, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, timeout=120, check=False,
            )
    (output / f"{name}.status").write_text(f"{result.returncode}\n")
    require(result.returncode == 0, f"{name} failed with exit {result.returncode}")
    return read_regular(output / f"{name}.stdout", 1 << 20)[0]


def check(args):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.plan_id) is not None, "invalid plan ID")
    for name in ("client_sha256", "audit_key_sha256", "descriptor_sha256", "rootfs_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", getattr(args, name)) is not None,
                f"invalid {name}")
    require(re.fullmatch(r"runtime/python@[0-9]+\.[0-9]+\.[0-9]+", args.reference) is not None,
            "expected an exact Python pack version")
    home_info = args.mvm_home.lstat()
    require(stat.S_ISDIR(home_info.st_mode) and home_info.st_uid == os.getuid()
            and stat.S_IMODE(home_info.st_mode) == 0o700, "MVM_HOME must be private and owned")
    client = args.client.resolve(strict=True)
    require(sha(read_regular(client, 1 << 30)[0]) == args.client_sha256, "client hash mismatch")
    key_path = args.mvm_home / "keys" / "host-signer.pub"
    key, key_identity = read_regular(key_path, 32)
    require(len(key) == 32 and sha(key) == args.audit_key_sha256, "setup key changed")
    audit_path = args.mvm_home / "audit" / "local.jsonl"
    chain, chain_identity = read_regular(audit_path)
    entries = session_entries(chain, args.plan_id)
    receipt, _ = read_regular(args.receipt)
    receipt_semantics(document(receipt), args.audit_key_sha256)
    args.output.mkdir(mode=0o700)  # Exclusive output claim; never overwrite/retry.
    (args.output / "receipt.json").write_bytes(receipt)
    (args.output / "audit-before.jsonl").write_bytes(chain)
    (args.output / "setup-public-key").write_bytes(key)
    environment = {
        "PATH": os.defpath, "HOME": str(args.output / "home"),
        "TMPDIR": str(args.output / "tmp"),
        "MVM_HOME": str(args.mvm_home), "LC_ALL": "C", "NO_COLOR": "1",
    }
    (args.output / "home").mkdir(mode=0o700)
    (args.output / "tmp").mkdir(mode=0o700)
    run_verifier(client, [
        "trust", "receipt", "verify", str(args.output / "receipt.json"),
        "--pubkey", str(args.output / "setup-public-key"),
    ], environment, args.output, "receipt-verifier")
    verified = run_verifier(client, [
        "trust", "audit", "verify", args.plan_id, "--tenant", "local", "--json",
    ], environment, args.output, "session-verifier")
    after, after_identity = read_regular(audit_path)
    require(after_identity == chain_identity and after.startswith(chain),
            "verification replaced or rewrote the input audit chain")
    require(read_regular(key_path, 32) == (key, key_identity), "verification changed setup key")
    require(sha(read_regular(client, 1 << 30)[0]) == args.client_sha256, "client changed")
    session_semantics(document(verified), entries, args.plan_id, args.reference,
                      args.descriptor_sha256, args.rootfs_sha256)
    return {
        "schema_version": 1, "kind": "verified-consumer-session-components",
        "plan_id": args.plan_id, "reference": args.reference,
        "descriptor_sha256": args.descriptor_sha256, "rootfs_sha256": args.rootfs_sha256,
        "client_sha256": args.client_sha256, "audit_key_sha256": args.audit_key_sha256,
        "receipt_sha256": sha(receipt), "audit_snapshot_sha256": sha(chain),
        "verifier_final_self_outcome_covered": False,
        "protected_observer_receipt": False,
        "receipt_to_plan_process_linkage": "must be established by enclosing isolated runner",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "mvm-home", "receipt", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("client-sha256", "audit-key-sha256", "plan-id", "reference",
                 "descriptor-sha256", "rootfs-sha256"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        report = check(args)
        with (args.output / "components.json").open("x") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"check-python-consumer-session: {error}\n")


if __name__ == "__main__":
    main()
