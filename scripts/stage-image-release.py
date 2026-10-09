#!/usr/bin/env python3
"""Verify signed image evidence and stage immutable release assets.

This is a release-input gate, not registry publication. The registry publisher
continues to refuse image manifests until release upload and client gates pass.
"""

import argparse
import importlib.util
import json
import stat
import subprocess
import tempfile
from pathlib import Path


RELEASE_NAMES = frozenset((
    "rootfs.ext4", "rootfs.verity", "rootfs.roothash", "mvm-meta.json",
    "rootfs.signature.json", "provenance.json", "provenance.signature.json",
))
EVIDENCE_NAMES = RELEASE_NAMES | frozenset((
    "asset-report.json", "composition.json", "candidate.json",
    "image-descriptor.json", "image-evidence.json", "image-evidence.sigstore.json",
))


class StageError(Exception):
    """Signed evidence cannot safely become release assets."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise StageError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


signer = helper("sign-composed-image.py", "sign_composed_image_stage")
reproducer = helper("reproduce-app-layer.py", "reproduce_app_layer_stage")
binder = helper("bind-image-candidate.py", "bind_image_candidate_stage")


def read_json(path):
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=reproducer.unique_object)
    except (OSError, UnicodeError, ValueError, reproducer.ReproductionError) as error:
        raise StageError(f"invalid JSON in {path.name}") from error


def record(path):
    digest, size = reproducer.digest_file(path)
    return {"sha256": digest, "size": size}


def verify_bundle(blob, bundle):
    try:
        subprocess.run(
            ["cosign", "verify-blob", str(blob), "--bundle", str(bundle),
             "--certificate-identity", signer.PUBLISHER_IDENTITY,
             "--certificate-oidc-issuer", signer.PUBLISHER_ISSUER],
            check=True, capture_output=True, timeout=300,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise StageError(f"publisher signature verification failed for {blob.name}") from error


def check_evidence(snapshot, reference, source, images_lock):
    if {entry.name for entry in snapshot.iterdir()} != EVIDENCE_NAMES:
        raise StageError("signed evidence has missing or extra files")
    evidence = read_json(snapshot / "image-evidence.json")
    if (not isinstance(evidence, dict)
            or set(evidence) != {"schema_version", "kind", "reference", "base_set",
                                  "publisher_identity", "assets"}
            or evidence["schema_version"] != 1
            or evidence["kind"] != "signed-image-evidence-not-published"
            or evidence["reference"] != reference
            or evidence["publisher_identity"] != signer.PUBLISHER_IDENTITY
            or not isinstance(evidence["assets"], dict)
            or set(evidence["assets"]) != EVIDENCE_NAMES - {
                "image-evidence.json", "image-evidence.sigstore.json"}):
        raise StageError("signed evidence descriptor is invalid")
    for name, expected in evidence["assets"].items():
        if expected != record(snapshot / name):
            raise StageError(f"signed evidence digest differs for {name}")
    descriptor = read_json(snapshot / "image-descriptor.json")
    builder = helper("build-packs.py", "build_packs_stage")
    try:
        builder.validate_built_image_descriptor(descriptor, reference)
    except SystemExit as error:
        raise StageError("built image descriptor is invalid") from error
    if descriptor["base_set"] != evidence["base_set"]:
        raise StageError("signed descriptor base pin differs from evidence")
    for asset in descriptor["assets"].values():
        name = asset["name"]
        if asset != {"name": name, **record(snapshot / name)}:
            raise StageError(f"release asset digest differs for {name}")
    try:
        signer.check_images_lock(images_lock, descriptor["base_set"])
        signer.check_boot_sidecar(snapshot / "mvm-meta.json", reproducer)
    except signer.SigningError as error:
        raise StageError(str(error)) from error
    if not signer.REFERENCE.fullmatch(reference):
        raise StageError("invalid pack reference")
    try:
        metadata = builder.parse_pack_toml(source)
    except SystemExit as error:
        raise StageError("pack source intent is invalid") from error
    intent = metadata["image_build"]
    if (metadata["version"] != reference.partition("@")[2]
            or intent is None
            or any(descriptor[key] != intent[key] for key in (
                "platform", "base_set", "release"))):
        raise StageError("pack source intent differs from signed descriptor")
    candidate = read_json(snapshot / "candidate.json")
    if (not isinstance(candidate, dict)
            or candidate.get("pack_source") != record(source)):
        raise StageError("pack source bytes differ from signed candidate")
    with tempfile.TemporaryDirectory(prefix="mvm-pack-recheck-", dir="/tmp") as temporary:
        composed = Path(temporary)
        for name in signer.INPUT_ASSETS | {"composition.json"}:
            binder.copy_regular(snapshot / name, composed / name)
        try:
            composition = signer.validate_snapshot(
                composed, snapshot / "candidate.json", reference, reproducer)
        except signer.SigningError as error:
            raise StageError(str(error)) from error
        exact = composed / "exact-assets"
        exact.mkdir(mode=0o700)
        for name in signer.INPUT_ASSETS:
            binder.copy_regular(snapshot / name, exact / name)
        try:
            reproducer.verify_output(exact)
        except reproducer.ReproductionError as error:
            raise StageError("composed asset report is invalid") from error
    if composition["base_set"] != descriptor["base_set"]:
        raise StageError("composition base pin differs from signed descriptor")
    provenance = read_json(snapshot / "provenance.json")
    try:
        subject = provenance["subject"]
        predicate = provenance["predicate"]
        definition = predicate["buildDefinition"]
        dependencies = definition["resolvedDependencies"]
        builder_id = predicate["runDetails"]["builder"]["id"]
        invocation = predicate["runDetails"]["metadata"]["invocationId"]
    except (KeyError, IndexError, TypeError) as error:
        raise StageError("provenance statement is incomplete") from error
    lock_sha = record(images_lock)["sha256"]
    required = (
        {"uri": "mvm/images.lock", "digest": {"sha256": lock_sha}},
        {"uri": "image-set.json", "digest": {
            "sha256": descriptor["base_set"]["manifest_sha256"]}},
        {"uri": "candidate.json", "digest": {
            "sha256": record(snapshot / "candidate.json")["sha256"]}},
        {"uri": "application-layer/rootfs.ext4", "digest": {
            "sha256": composition["application_layer_sha256"]}},
    )
    if (provenance.get("_type") != "https://in-toto.io/Statement/v1"
            or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
            or subject != [{"name": "rootfs.ext4", "digest": {
                "sha256": record(snapshot / "rootfs.ext4")["sha256"]}}]
            or definition.get("externalParameters") != {
                "reference": reference, "base_set": descriptor["base_set"]}
            or definition.get("internalParameters") != {
                "verifier_sha256": composition["verifier_sha256"]}
            or not isinstance(dependencies, list)
            or any(item not in dependencies for item in required)
            or builder_id != signer.PUBLISHER_IDENTITY
            or not isinstance(invocation, str)
            or not invocation.startswith(
                "https://github.com/tinylabscom/mvm-packs/actions/runs/")):
        raise StageError("provenance does not bind the image and current base lock")
    for name, bundle in (("rootfs.ext4", "rootfs.signature.json"),
                         ("provenance.json", "provenance.signature.json"),
                         ("image-evidence.json", "image-evidence.sigstore.json")):
        verify_bundle(snapshot / name, snapshot / bundle)


def stage(evidence_dir, reference, source, images_lock, output):
    evidence_dir, source, images_lock, output = map(
        Path, (evidence_dir, source, images_lock, output))
    if output.exists() or output.is_symlink():
        raise StageError("output must be a new directory")
    if not stat.S_ISDIR(evidence_dir.lstat().st_mode):
        raise StageError("signed evidence must be a directory, not a link")
    with tempfile.TemporaryDirectory(prefix="mvm-pack-stage-", dir="/tmp") as temporary:
        snapshot = Path(temporary) / "evidence"
        snapshot.mkdir(mode=0o700)
        if {entry.name for entry in evidence_dir.iterdir()} != EVIDENCE_NAMES:
            raise StageError("signed evidence has missing or extra files")
        try:
            for name in sorted(EVIDENCE_NAMES):
                binder.copy_regular(evidence_dir / name, snapshot / name)
            copied_source = (Path(temporary) / "pack-sources" /
                             source.parent.parent.name / source.parent.name / "pack.toml")
            copied_source.parent.mkdir(parents=True, mode=0o700)
            copied_lock = Path(temporary) / "images.lock"
            binder.copy_regular(source, copied_source)
            binder.copy_regular(images_lock, copied_lock)
        except (OSError, binder.CandidateError) as error:
            raise StageError("input snapshot refused a missing, linked or special file") from error
        check_evidence(snapshot, reference, copied_source, copied_lock)
        with tempfile.TemporaryDirectory(prefix=".mvm-pack-release-", dir=output.parent) as staging:
            release = Path(staging) / "release"
            release.mkdir(mode=0o700)
            for name in sorted(RELEASE_NAMES):
                binder.copy_regular(snapshot / name, release / name)
            binder.copy_regular(snapshot / "image-descriptor.json", release / "image-descriptor.json")
            try:
                reproducer.publish_noclobber(release, output)
            except reproducer.ReproductionError as error:
                raise StageError("atomic no-clobber output is unavailable") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvm-images-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        stage(args.evidence, args.reference, args.pack_source, args.mvm_images_lock,
              args.output)
    except (OSError, StageError) as error:
        parser.exit(1, f"stage-image-release: {error}\n")


if __name__ == "__main__":
    main()
