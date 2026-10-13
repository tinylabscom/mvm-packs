#!/usr/bin/env python3
"""Judge one released-client boot of the signed Python image and record it.

The caller boots the staged deployment with the released mvmctl and captures
the guest command's exit status, stdout and stderr itself. This check accepts
the run only when the command exited 0, printed exactly one CPython 3.12
version line, and the booted files still match the signed descriptor. It
always writes the report, then exits non-zero on any mismatch.

The report is unsigned job output. It records what the job observed; it is
not the observed publication witness and authorizes nothing by itself.
"""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


PYTHON_VERSION = re.compile(rb"Python 3\.12\.(0|[1-9][0-9]{0,2})\n")
BOOTED_ASSETS = {
    "rootfs": "rootfs.ext4",
    "verity": "rootfs.verity",
    "roothash": "rootfs.roothash",
    "mvm_meta": "mvm-meta.json",
}
MAX_STREAM = 1 << 20


class ProbeError(Exception):
    """The probe did not demonstrate a working signed image."""


def record(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ProbeError(f"{path.name} must be a regular file, not a link")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def read_stream(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ProbeError(f"{path.name} must be a regular file, not a link")
    data = path.read_bytes()
    if len(data) > MAX_STREAM:
        raise ProbeError(f"{path.name} exceeds {MAX_STREAM} bytes")
    return data


def booted_assets(descriptor, deployment):
    """Require the booted files to be exactly the signed descriptor's assets."""
    checked = {}
    for role, name in BOOTED_ASSETS.items():
        try:
            expected = descriptor["assets"][role]
        except (KeyError, TypeError) as error:
            raise ProbeError(f"descriptor has no {role} asset") from error
        if not isinstance(expected, dict) or expected.get("name") != name:
            raise ProbeError(f"descriptor {role} asset is not {name}")
        actual = record(deployment / name)
        if actual != {"sha256": expected.get("sha256"), "size": expected.get("size")}:
            raise ProbeError(f"booted {name} differs from the signed descriptor")
        checked[name] = actual
    return checked


def judge(exit_code, stdout):
    if exit_code != 0:
        raise ProbeError(f"guest command exited {exit_code}")
    if not PYTHON_VERSION.fullmatch(stdout):
        raise ProbeError("guest stdout is not exactly one CPython 3.12 version line")
    return stdout.decode("ascii").strip()


def check(args):
    """Return (report, error); the report is complete either way."""
    stdout = read_stream(args.stdout)
    stderr = read_stream(args.stderr)
    descriptor = json.loads(args.descriptor.read_bytes())
    report = {
        "schema_version": 1,
        "kind": "released-client-boot-probe",
        "reference": args.reference,
        "client": {
            "tag": args.mvmctl_tag,
            "executable": record(args.mvmctl),
        },
        "descriptor": record(args.descriptor),
        "command": json.loads(args.command),
        "exit_code": args.exit_code,
        "stdout": {**record(args.stdout), "text": stdout.decode("utf-8", "replace")},
        "stderr": {**record(args.stderr), "text": stderr.decode("utf-8", "replace")},
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        },
    }
    try:
        report["booted_assets"] = booted_assets(descriptor, args.deployment)
        report["python_version"] = judge(args.exit_code, stdout)
    except ProbeError as error:
        report["result"] = "refused"
        report["reason"] = str(error)
        return report, error
    report["result"] = "passed"
    return report, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--mvmctl", required=True, type=Path)
    parser.add_argument("--mvmctl-tag", required=True)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--deployment", required=True, type=Path)
    parser.add_argument("--command", required=True, help="JSON array of the executed argv")
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--stderr", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, error = check(args)
    except (OSError, ValueError, UnicodeError, ProbeError) as failure:
        parser.exit(1, f"check-python-boot-probe: {failure}\n")
    try:
        with args.report.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as failure:
        parser.exit(1, f"check-python-boot-probe: cannot write report: {failure}\n")
    if error is not None:
        parser.exit(1, f"check-python-boot-probe: {error}\n")
    print(f"released client booted {args.reference}: {report['python_version']}")


if __name__ == "__main__":
    main()
