#!/usr/bin/env python3
"""Strict publication-only witness contract parser, not a producer or credential.

These APIs validate signed bytes and raw result bindings. They do not establish
that a protected workflow executed the probes; a reviewed runner must establish
that origin before this parser can be integrated at the publication boundary.
No API here signs imported reports or produces positive runtime evidence.
"""

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


class WitnessError(Exception):
    """Witness bytes are incomplete, unsafe, unsupported or inconsistent."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise WitnessError(f"required helper {filename} unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stager = helper("stage-image-release.py", "stage_observed_witness")
signer = stager.signer
LIMIT = 4 << 20
HEX = re.compile(r"[0-9a-f]{64}\Z")
MODES = ("transient", "persistent")
REPORT_FIELDS = {
    "schema_version", "kind", "source", "reference", "descriptor",
    "signed_image_evidence", "images_lock", "base_set", "client", "policy", "modes",
}
CLIENT_FIELDS = {"repository", "tag", "architecture", "archive", "checksums",
                 "signature_bundle", "executable"}
CLIENT_ROLES = {"archive", "checksums", "signature_bundle", "executable"}


def shape(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise WitnessError(f"{label} has missing or unknown fields")


def file_record(value, *, empty=False, limit=64 << 30):
    shape(value, {"sha256", "size"}, "file record")
    if (not isinstance(value["sha256"], str) or not HEX.fullmatch(value["sha256"])
            or type(value["size"]) is not int
            or not (0 if empty else 1) <= value["size"] <= limit):
        raise WitnessError("invalid file digest or size")


def bounded_bytes(path, *, empty=False, limit=LIMIT):
    path = Path(path)
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise WitnessError("symlink paths are forbidden")
    # Bound reads even if a file grows; never read a device or FIFO.
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not (0 if empty else 1) <= info.st_size <= limit):
        raise WitnessError("input must be a bounded regular non-hardlinked file")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not nofollow or not nonblock:
        raise WitnessError("no-follow nonblocking file reads are unavailable")
    flags = os.O_RDONLY | nofollow | nonblock
    with os.fdopen(os.open(path, flags), "rb") as stream:
        current = os.fstat(stream.fileno())
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or (current.st_ino, current.st_dev, current.st_size) != (
                    info.st_ino, info.st_dev, info.st_size)):
            raise WitnessError("input changed before read")
        data = stream.read(limit + 1)
    if len(data) != info.st_size:
        raise WitnessError("input changed or exceeded read bound")
    return data


def digest(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def exact(value, expected):
    """JSON equality that does not coerce booleans/floats to integer counts."""
    return json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WitnessError("duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(_):
        raise WitnessError("non-finite JSON number")
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise WitnessError("invalid bounded JSON") from error


def source_identity(environment):
    if any(not isinstance(value, str) for value in environment.values()):
        raise WitnessError("source identity fields must be strings")
    try:
        invocation = signer.check_identity(environment)
    except signer.SigningError as error:
        raise WitnessError(str(error)) from error
    return {
        "repository": environment["GITHUB_REPOSITORY"],
        "ref": environment["GITHUB_REF"],
        "sha": environment["GITHUB_SHA"],
        "workflow_ref": environment["GITHUB_WORKFLOW_REF"],
        "run_id": environment["GITHUB_RUN_ID"],
        "run_attempt": environment["GITHUB_RUN_ATTEMPT"],
        "invocation": invocation,
        "publisher_identity": signer.PUBLISHER_IDENTITY,
    }


def resolve_policy(binding, trusted_policies):
    """Resolve only workflow-owned allowlisted bytes, never an author checklist.

    The caller's trusted registry maps (backend, version, sha256) to exact
    protected-source policy bytes. It is not read from the witness directory.
    """
    shape(binding, {"backend", "version", "sha256"}, "policy binding")
    if (not isinstance(binding["backend"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", binding["backend"])
            or type(binding["version"]) is not int or binding["version"] <= 0
            or not isinstance(binding["sha256"], str) or not HEX.fullmatch(binding["sha256"])):
        raise WitnessError("invalid backend-specific policy binding")
    key = (binding["backend"], binding["version"], binding["sha256"])
    raw = trusted_policies.get(key)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMIT:
        raise WitnessError("unknown backend, policy or version")
    if digest(raw)["sha256"] != binding["sha256"]:
        raise WitnessError("trusted policy digest differs")
    policy = parse_json(raw)
    shape(policy, {"schema_version", "backend", "version", "checks"}, "trusted policy")
    if (type(policy["schema_version"]) is not int or policy["schema_version"] != 1
            or type(policy["version"]) is not int
            or policy["backend"] != binding["backend"] or policy["version"] != binding["version"]):
        raise WitnessError("unsupported or mismatched trusted policy")
    shape(policy["checks"], MODES, "policy modes")
    for mode in MODES:
        checks = policy["checks"][mode]
        if not isinstance(checks, dict) or not 1 <= len(checks) <= 64:
            raise WitnessError("policy must declare a nonempty bounded check set for both modes")
        required = 0
        for name, check in checks.items():
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
                raise WitnessError("invalid trusted check name")
            if isinstance(check, dict) and check.get("applicability") == "inapplicable":
                shape(check, {"applicability"}, "inapplicable policy check")
            else:
                shape(check, {"applicability", "value_type", "expected"}, "required policy check")
                types = {"integer": int, "string": str}
                if (check["applicability"] != "required"
                        or not isinstance(check["value_type"], str)
                        or check["value_type"] not in types
                        or type(check["expected"]) is not types[check["value_type"]]):
                    raise WitnessError("invalid typed expected policy measurement")
                required += 1
        if required == 0:
            raise WitnessError("each mode requires nonempty applicable checks")
    return policy


def validate_report(report, trusted_policies):
    """Strict structural parser only: NOT publication authorization."""
    shape(report, REPORT_FIELDS, "report")
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["kind"] != "observed-publication-witness"):
        raise WitnessError("unsupported witness schema")
    if not isinstance(report["reference"], str) or not signer.REFERENCE.fullmatch(report["reference"]):
        raise WitnessError("invalid exact pack reference")
    source = report["source"]
    shape(source, {"repository", "ref", "sha", "workflow_ref", "run_id",
                   "run_attempt", "invocation", "publisher_identity"}, "source")
    environment = {f"GITHUB_{key}": source[field] for key, field in (
        ("REPOSITORY", "repository"), ("REF", "ref"), ("SHA", "sha"),
        ("WORKFLOW_REF", "workflow_ref"), ("RUN_ID", "run_id"),
        ("RUN_ATTEMPT", "run_attempt"))}
    if source != source_identity(environment):
        raise WitnessError("source invocation or publisher identity differs")
    file_record(report["descriptor"], limit=LIMIT)
    file_record(report["images_lock"], limit=LIMIT)
    base = report["base_set"]
    shape(base, {"repository", "release_tag", "manifest_sha256"}, "base set")
    if (base["repository"] != "tinylabscom/mvm-images"
            or not isinstance(base["release_tag"], str)
            or not re.fullmatch(r"image-set/v[0-9]+\.[0-9]+\.[0-9]+", base["release_tag"])
            or not isinstance(base["manifest_sha256"], str)
            or not HEX.fullmatch(base["manifest_sha256"])):
        raise WitnessError("invalid base pin")
    shape(report["signed_image_evidence"], stager.EVIDENCE_NAMES, "signed image evidence")
    for name, value in report["signed_image_evidence"].items():
        file_record(value, limit=LIMIT if name.endswith(".json") else 64 << 30)
    if report["descriptor"] != report["signed_image_evidence"]["image-descriptor.json"]:
        raise WitnessError("descriptor differs from signed evidence")
    client = report["client"]
    shape(client, CLIENT_FIELDS, "released client")
    if (client["repository"] != "tinylabscom/mvm"
            or not isinstance(client["tag"], str)
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", client["tag"])
            or client["architecture"] not in ("x86_64", "aarch64")):
        raise WitnessError("invalid exact released client")
    for key in CLIENT_ROLES:
        file_record(client[key])
    if sum(value["size"] for value in (
            *report["signed_image_evidence"].values(),
            *(client[key] for key in CLIENT_ROLES))) > 64 << 30:
        raise WitnessError("aggregate image/client bytes exceed resource bound")
    policy = resolve_policy(report["policy"], trusted_policies)
    shape(report["modes"], MODES, "probe modes")
    for mode in MODES:
        value = report["modes"][mode]
        shape(value, {"transcript", "commands", "observations"}, mode)
        file_record(value["transcript"], limit=LIMIT)
        commands = value["commands"]
        if not isinstance(commands, list) or not 1 <= len(commands) <= 64:
            raise WitnessError("mode must retain bounded actual commands")
        for command in commands:
            shape(command, {"argv", "exit_code", "stdout", "stderr"}, "command")
            argv = command["argv"]
            if (not isinstance(argv, list) or not 1 <= len(argv) <= 64
                    or any(not isinstance(arg, str) or not arg or len(arg) > 4096
                           or any(ord(char) < 32 for char in arg) for arg in argv)
                    or type(command["exit_code"]) is not int or command["exit_code"] != 0):
                raise WitnessError("absent, failed or malformed actual command")
            for stream in ("stdout", "stderr"):
                file_record(command[stream], empty=True, limit=LIMIT)
        expected = policy["checks"][mode]
        observations = value["observations"]
        shape(observations, expected, "observations")
        for check, requirement in expected.items():
            observed = observations[check]
            shape(observed, {"command_index", "state", "value"}, check)
            if (type(observed["command_index"]) is not int
                    or not 0 <= observed["command_index"] < len(commands)):
                raise WitnessError("observation must identify an actual retained command")
            if requirement["applicability"] == "inapplicable":
                if observed["state"] != "not-applicable" or observed["value"] is not None:
                    raise WitnessError("N/A requires explicit trusted backend inapplicability")
            elif (observed["state"] != "observed"
                  or type(observed["value"]) is not type(requirement["expected"])
                  or observed["value"] != requirement["expected"]):
                raise WitnessError(f"{mode} observation {check} is absent, unknown or failed")
        raw_size = value["transcript"]["size"] + sum(
            command[stream]["size"] for command in commands for stream in ("stdout", "stderr"))
        if raw_size > 32 << 20:
            raise WitnessError("per-mode retained raw bytes exceed resource bound")
    return policy


def validate_raw(report, directory):
    """Parse retained raw observation stdout and bind it to the signed report."""
    directory = Path(directory)
    retained = {"witness.json", "witness.sigstore.json"}
    for mode in MODES:
        value = report["modes"][mode]
        filename = f"{mode}.json"
        retained.add(filename)
        raw = bounded_bytes(directory / filename)
        if digest(raw) != value["transcript"]:
            raise WitnessError(f"{mode} raw transcript hash differs")
        transcript = parse_json(raw)
        shape(transcript, {"schema_version", "source", "descriptor", "client", "policy",
                           "mode", "commands"}, "raw transcript")
        if (type(transcript["schema_version"]) is not int or transcript["schema_version"] != 1
                or transcript["mode"] != mode or not exact(transcript["commands"], value["commands"])
                or any(not exact(transcript[key], report[key]) for key in ("source", "descriptor", "client", "policy"))):
            raise WitnessError("raw result source/candidate/client/content binding differs")
        observed = {}
        for index, command in enumerate(value["commands"]):
            streams = {}
            for stream in ("stdout", "stderr"):
                name = f"{mode}-{index}.{stream}"
                retained.add(name)
                data = bounded_bytes(directory / name, empty=True)
                if digest(data) != command[stream]:
                    raise WitnessError("raw command stream bytes differ")
                streams[stream] = data
            result = parse_json(streams["stdout"])
            shape(result, {"schema_version", "source", "descriptor", "client", "policy",
                           "mode", "observations"}, "raw observation result")
            if (type(result["schema_version"]) is not int or result["schema_version"] != 1
                    or result["mode"] != mode
                    or any(not exact(result[key], report[key]) for key in ("source", "descriptor", "client", "policy"))
                    or not isinstance(result["observations"], dict)):
                raise WitnessError("raw observation result binding differs")
            for check, value_observed in result["observations"].items():
                if check in observed:
                    raise WitnessError("duplicate raw observation")
                shape(value_observed, {"state", "value"}, "raw observed measurement")
                observed[check] = {"command_index": index, **value_observed}
        if not exact(observed, value["observations"]):
            raise WitnessError("report observations differ from retained raw results")
    if {entry.name for entry in directory.iterdir()} != retained:
        raise WitnessError("witness directory has missing or extra files")


def verify_report_signature(blob, bundle, source):
    """Verify only the current publisher identity and its protected source commit."""
    try:
        subprocess.run(
            ["cosign", "verify-blob", str(blob), "--bundle", str(bundle),
             "--certificate-identity", signer.PUBLISHER_IDENTITY,
             "--certificate-oidc-issuer", signer.PUBLISHER_ISSUER,
             "--certificate-github-workflow-repository", source["repository"],
             "--certificate-github-workflow-ref", source["ref"],
             "--certificate-github-workflow-sha", source["sha"]],
            check=True, capture_output=True, timeout=300,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise WitnessError("witness signature/source verification failed") from error


def verify(*, directory, evidence, reference, pack_source, images_lock,
           client_files, environment, trusted_policies):
    """Verify contract bytes/signatures; NOT proof of runner origin or client release.

    A future protected producer must authenticate/extract the released client,
    execute the probes and guarantee the raw stdout came from its own observer.
    Until that integration is reviewed this function must not authorize upload.
    """
    directory, evidence = Path(directory), Path(evidence)
    source = source_identity(environment)
    report_bytes = bounded_bytes(directory / "witness.json")
    report = parse_json(report_bytes)
    validate_report(report, trusted_policies)
    if report["source"] != source or report["reference"] != reference:
        raise WitnessError("witness source/run/attempt/reference differs from publication")
    shape(client_files, CLIENT_ROLES, "client files")
    if any(folder.is_symlink() or not stat.S_ISDIR(folder.lstat().st_mode)
           for folder in (directory, evidence)):
        raise WitnessError("input directories cannot be links")
    if {entry.name for entry in evidence.iterdir()} != stager.EVIDENCE_NAMES:
        raise WitnessError("evidence file set differs")
    with tempfile.TemporaryDirectory(
            prefix="mvm-witness-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        private = Path(temporary)
        snapshot = private / "evidence"
        snapshot.mkdir(mode=0o700)
        try:
            for name, expected in report["signed_image_evidence"].items():
                # Existing copier refuses linked/special source files.
                if any(part.is_symlink() for part in (evidence / name, *(evidence / name).parents)):
                    raise WitnessError("linked evidence path")
                stager.binder.copy_regular(evidence / name, snapshot / name, max_bytes=expected["size"])
                if stager.record(snapshot / name) != expected:
                    raise WitnessError(f"evidence bytes differ: {name}")
            lock = private / "images.lock"
            lock.write_bytes(bounded_bytes(images_lock))
            if digest(lock.read_bytes()) != report["images_lock"]:
                raise WitnessError("images.lock bytes differ")
            source_path = (private / "pack-sources" / Path(pack_source).parent.parent.name /
                           Path(pack_source).parent.name / "pack.toml")
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes(bounded_bytes(pack_source))
            for role, path in client_files.items():
                # Hash large archives/executables using the existing streaming helper.
                copy = private / role
                path = Path(path)
                if any(part.is_symlink() for part in (path, *path.parents)):
                    raise WitnessError("linked client path")
                stager.binder.copy_regular(path, copy, max_bytes=report["client"][role]["size"])
                if stager.record(copy) != report["client"][role]:
                    raise WitnessError(f"client bytes differ: {role}")
            stager.check_evidence(snapshot, reference, source_path, lock)
        except (stager.StageError, stager.binder.CandidateError) as error:
            raise WitnessError(str(error)) from error
        descriptor = parse_json(bounded_bytes(snapshot / "image-descriptor.json"))
        if descriptor["base_set"] != report["base_set"]:
            raise WitnessError("descriptor base pin differs")
        if descriptor["platform"] != "linux/" + report["client"]["architecture"]:
            raise WitnessError("candidate platform differs from released client architecture")
        composition = parse_json(bounded_bytes(snapshot / "composition.json"))
        provenance = parse_json(bounded_bytes(snapshot / "provenance.json"))
        expected_provenance = signer.provenance(
            reference, composition, stager.record(snapshot / "rootfs.ext4"),
            source["invocation"], source["sha"], report["images_lock"]["sha256"])
        if not exact(provenance, expected_provenance):
            raise WitnessError("signed image provenance source/run/attempt differs from witness")
        raw_snapshot = private / "raw"
        raw_snapshot.mkdir(mode=0o700)
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise WitnessError("witness directory cannot be a link")
        # Fixed finite file names only; no report-controlled paths.
        names = {"witness.json", "witness.sigstore.json", "transient.json", "persistent.json"}
        for mode in MODES:
            for index in range(len(report["modes"][mode]["commands"])):
                names.update((f"{mode}-{index}.stdout", f"{mode}-{index}.stderr"))
        if {entry.name for entry in directory.iterdir()} != names:
            raise WitnessError("witness directory has missing or extra files")
        for name in names:
            (raw_snapshot / name).write_bytes(bounded_bytes(
                directory / name, empty=name.endswith((".stdout", ".stderr"))))
        if (raw_snapshot / "witness.json").read_bytes() != report_bytes:
            raise WitnessError("report changed during verification")
        validate_raw(report, raw_snapshot)
        verify_report_signature(raw_snapshot / "witness.json",
                                raw_snapshot / "witness.sigstore.json", source)
    return report
