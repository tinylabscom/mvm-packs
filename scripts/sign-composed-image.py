#!/usr/bin/env python3
"""Sign a reproduced pack image and its provenance under the main publisher identity.

The output is evidence for a later image release, not a published pack. It
contains no boot sidecar or registry manifest and must not be served by pull.
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path


INPUT_ASSETS = frozenset(("rootfs.ext4", "rootfs.verity", "rootfs.roothash", "asset-report.json"))
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REFERENCE = re.compile(r"[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*@[0-9]+\.[0-9]+\.[0-9]+\Z")


class SigningError(Exception):
    """The signed output could not be proven eligible."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise SigningError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = helper("publisher_identity.py", "publisher_identity_sign")
PUBLISHER_IDENTITY = publisher.CURRENT_IDENTITY
PUBLISHER_ISSUER = publisher.PUBLISHER_ISSUER
WORKFLOW_REF = PUBLISHER_IDENTITY.removeprefix("https://github.com/")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def strict_json(path, reproducer):
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=reproducer.unique_object)
    except (UnicodeError, ValueError, reproducer.ReproductionError) as error:
        raise SigningError(f"invalid JSON in {path.name}") from error


def record(path, reproducer):
    digest, size = reproducer.digest_file(path)
    if size <= 0:
        raise SigningError(f"empty input {path.name}")
    return {"sha256": digest, "size": size}


def check_identity(environment):
    if (
        environment.get("GITHUB_REPOSITORY") != "tinylabscom/mvm-packs"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF
    ):
        raise SigningError("publisher workflow must be the main publish.yml identity")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    if not (0 < len(run_id) <= 20 and run_id.isascii() and run_id.isdecimal()
            and int(run_id) > 0 and 0 < len(attempt) <= 10 and attempt.isascii()
            and attempt.isdecimal() and int(attempt) > 0):
        raise SigningError("publisher workflow run identity is invalid")
    source_sha = environment.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise SigningError("publisher workflow source commit is invalid")
    return f"https://github.com/tinylabscom/mvm-packs/actions/runs/{run_id}/attempts/{attempt}"


def sign_and_verify(path, bundle):
    """Verify the actual OIDC certificate identity before accepting any bundle."""
    if os.environ.get("COSIGN_KEY"):
        raise SigningError("key-based signing is forbidden for published image evidence")
    try:
        subprocess.run(
            ["cosign", "sign-blob", "--yes", "--bundle", str(bundle), str(path)],
            check=True, capture_output=True, timeout=300,
        )
        subprocess.run(
            ["cosign", "verify-blob", str(path), "--bundle", str(bundle),
             "--certificate-identity", PUBLISHER_IDENTITY,
             "--certificate-oidc-issuer", PUBLISHER_ISSUER],
            check=True, capture_output=True, timeout=300,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SigningError(f"keyless signing or identity verification failed for {path.name}") from error
    if not bundle.is_file() or bundle.stat().st_size == 0:
        raise SigningError(f"signature bundle missing for {path.name}")


def validate_snapshot(composed, candidate_path, reference, reproducer):
    if not REFERENCE.fullmatch(reference):
        raise SigningError("pack reference must be an exact versioned namespace/name@version")
    if {entry.name for entry in composed.iterdir()} != INPUT_ASSETS | {"composition.json"}:
        raise SigningError("composed image has missing or extra files")
    composition = strict_json(composed / "composition.json", reproducer)
    expected_fields = {
        "schema_version", "kind", "base_set", "candidate_sha256",
        "application_layer_sha256", "verifier_sha256", "assets",
    }
    if (not isinstance(composition, dict) or set(composition) != expected_fields
            or type(composition["schema_version"]) is not int
            or composition["schema_version"] != 1
            or composition["kind"] != "unsigned-composed-image"):
        raise SigningError("composed image report has an unsupported shape")
    base = composition["base_set"]
    if (not isinstance(base, dict)
            or set(base) != {"repository", "release_tag", "manifest_sha256"}
            or base["repository"] != "tinylabscom/mvm-images"
            or not isinstance(base["release_tag"], str)
            or not re.fullmatch(r"image-set/v[0-9]+\.[0-9]+\.[0-9]+", base["release_tag"])
            or not isinstance(base["manifest_sha256"], str)
            or not HEX64.fullmatch(base["manifest_sha256"])):
        raise SigningError("composed image base set is invalid")
    for key in ("candidate_sha256", "application_layer_sha256", "verifier_sha256"):
        if not isinstance(composition[key], str) or not HEX64.fullmatch(composition[key]):
            raise SigningError(f"invalid composed image {key}")
    if record(candidate_path, reproducer)["sha256"] != composition["candidate_sha256"]:
        raise SigningError("candidate digest differs from composition report")
    candidate = strict_json(candidate_path, reproducer)
    candidate_fields = {
        "schema_version", "kind", "platform", "pack_source", "base_set",
        "signed_root_manifest", "signed_root_bundle", "verifier_sha256",
        "verification_scope", "base_artifacts", "application_layer",
    }
    if (not isinstance(candidate, dict) or set(candidate) != candidate_fields
            or candidate.get("schema_version") != 1
            or candidate.get("kind") != "unsigned-image-candidate"
            or candidate.get("verification_scope") != "selected-base-artifacts-only"
            or candidate.get("base_set") != base
            or candidate.get("verifier_sha256") != composition["verifier_sha256"]
            or not isinstance(candidate.get("application_layer"), dict)
            or not isinstance(candidate["application_layer"].get("rootfs.ext4"), dict)
            or candidate["application_layer"]["rootfs.ext4"].get("sha256")
                != composition["application_layer_sha256"]):
        raise SigningError("candidate binding differs from composition report")
    if not isinstance(composition["assets"], dict) or set(composition["assets"]) != INPUT_ASSETS:
        raise SigningError("composition report asset set is invalid")
    for name in sorted(INPUT_ASSETS):
        if composition["assets"][name] != record(composed / name, reproducer):
            raise SigningError(f"composed asset digest differs for {name}")
    return composition


def check_images_lock(path, base):
    if path.name != "images.lock":
        raise SigningError("mvm images.lock must retain its source name")
    try:
        lock = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise SigningError("mvm images.lock is unreadable or invalid") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != 2:
        raise SigningError("mvm images.lock has an unsupported schema")
    image_set = lock.get("image_set")
    if (lock.get("repository") != base["repository"]
            or not isinstance(image_set, dict)
            or image_set.get("repository") != base["repository"]
            or image_set.get("release_tag") != base["release_tag"]
            or image_set.get("manifest_sha256") != base["manifest_sha256"]):
        raise SigningError("composed base set differs from current images.lock")


def provenance(reference, composition, rootfs_record, invocation, source_sha, lock_sha256):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "rootfs.ext4", "digest": {"sha256": rootfs_record["sha256"]}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": (
                    "https://github.com/tinylabscom/mvm-packs/blob/main/"
                    "README.packs.md#pack-image-composition-v1"
                ),
                "externalParameters": {
                    "reference": reference,
                    "base_set": composition["base_set"],
                },
                "internalParameters": {"verifier_sha256": composition["verifier_sha256"]},
                "resolvedDependencies": [
                    {"uri": "candidate.json", "digest": {"sha256": composition["candidate_sha256"]}},
                    {"uri": "application-layer/rootfs.ext4", "digest": {
                        "sha256": composition["application_layer_sha256"]}},
                    {"uri": "image-set.json", "digest": {
                        "sha256": composition["base_set"]["manifest_sha256"]}},
                    {"uri": "mvm/images.lock", "digest": {"sha256": lock_sha256}},
                    {"uri": f"git+https://github.com/tinylabscom/mvm-packs@{source_sha}",
                     "digest": {"gitCommit": source_sha}},
                ],
            },
            "runDetails": {
                "builder": {"id": PUBLISHER_IDENTITY},
                "metadata": {"invocationId": invocation},
            },
        },
    }


def prepare(composition_dir, candidate_path, reference, output, environment, images_lock):
    invocation = check_identity(environment)
    composition_dir, candidate_path, output, images_lock = map(
        Path, (composition_dir, candidate_path, output, images_lock)
    )
    if (output.name in ("", ".", "..") or output.exists() or output.is_symlink()
            or not stat.S_ISDIR(output.parent.resolve(strict=True).stat().st_mode)):
        raise SigningError("output must name a new directory")
    reproducer = helper("reproduce-app-layer.py", "reproduce_app_layer_sign")
    binder = helper("bind-image-candidate.py", "bind_image_candidate_sign")
    if not stat.S_ISDIR(composition_dir.lstat().st_mode):
        raise SigningError("composed input must be a directory, not a link")
    if {entry.name for entry in composition_dir.iterdir()} != INPUT_ASSETS | {"composition.json"}:
        raise SigningError("composed input has missing or extra files")
    with tempfile.TemporaryDirectory(prefix="mvm-pack-sign-", dir="/tmp") as temporary:
        private = Path(temporary)
        snapshot = private / "composed"
        snapshot.mkdir(mode=0o700)
        try:
            for name in sorted(INPUT_ASSETS | {"composition.json"}):
                binder.copy_regular(composition_dir / name, snapshot / name)
            copied_candidate = private / "candidate.json"
            binder.copy_regular(candidate_path, copied_candidate)
            copied_lock = private / "images.lock"
            binder.copy_regular(images_lock, copied_lock)
        except (OSError, binder.CandidateError) as error:
            raise SigningError("input snapshot refused a missing, linked or special file") from error
        composition = validate_snapshot(snapshot, copied_candidate, reference, reproducer)
        check_images_lock(copied_lock, composition["base_set"])
        lock_sha256 = record(copied_lock, reproducer)["sha256"]
        # The helper expects exactly the four filesystem outputs. Check its
        # asset-report semantics against an exact-set private directory.
        exact = private / "exact-assets"
        exact.mkdir(mode=0o700)
        for name in sorted(INPUT_ASSETS):
            shutil.copyfile(snapshot / name, exact / name)
        try:
            reproducer.verify_output(exact)
        except reproducer.ReproductionError as error:
            raise SigningError("composed asset report is invalid") from error
        with tempfile.TemporaryDirectory(prefix=".mvm-pack-signed-", dir=output.parent) as staging:
            staged = Path(staging) / "signed-image-evidence"
            staged.mkdir(mode=0o700)
            for name in sorted(INPUT_ASSETS | {"composition.json"}):
                shutil.copyfile(snapshot / name, staged / name)
            shutil.copyfile(copied_candidate, staged / "candidate.json")
            (staged / "provenance.json").write_bytes(json_bytes(provenance(
                reference, composition, record(staged / "rootfs.ext4", reproducer),
                invocation, environment["GITHUB_SHA"], lock_sha256,
            )))
            sign_and_verify(staged / "rootfs.ext4", staged / "rootfs.signature.json")
            sign_and_verify(staged / "provenance.json", staged / "provenance.signature.json")
            evidence = {
                "schema_version": 1,
                "kind": "signed-image-evidence-not-published",
                "reference": reference,
                "base_set": composition["base_set"],
                "publisher_identity": PUBLISHER_IDENTITY,
                "assets": {
                    name: record(staged / name, reproducer)
                    for name in (
                        "rootfs.ext4", "rootfs.verity", "rootfs.roothash",
                        "asset-report.json", "composition.json", "candidate.json",
                        "rootfs.signature.json",
                        "provenance.json", "provenance.signature.json",
                    )
                },
            }
            (staged / "image-evidence.json").write_bytes(json_bytes(evidence))
            sign_and_verify(staged / "image-evidence.json", staged / "image-evidence.sigstore.json")
            try:
                reproducer.publish_noclobber(staged, output)
            except reproducer.ReproductionError as error:
                raise SigningError("atomic no-clobber output is unavailable") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--composition", required=True, type=Path)
    parser.add_argument("--candidate-report", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mvm-images-lock", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        prepare(args.composition, args.candidate_report, args.reference, args.output,
                os.environ, args.mvm_images_lock)
    except (OSError, ValueError, SigningError) as error:
        parser.exit(1, f"sign-composed-image: {error}\n")


if __name__ == "__main__":
    main()
