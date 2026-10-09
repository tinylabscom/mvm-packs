#!/usr/bin/env python3
"""Publish a verified pack image only after draft assets round-trip byte-for-byte."""

import argparse
import importlib.util
import json
import os
import re
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class UploadError(Exception):
    """The release cannot safely be published."""


def helper(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise UploadError(f"required helper {filename} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stager = helper("stage-image-release.py", "stage_image_release_upload")
signer = helper("sign-composed-image.py", "sign_composed_image_upload")
reproducer = helper("reproduce-app-layer.py", "reproduce_app_layer_upload")
RELEASE_NAMES = stager.RELEASE_NAMES
ASSET_NAMES = RELEASE_NAMES | {"image-descriptor.json"}
REPOSITORY = "tinylabscom/mvm-packs"
API_ROOT = f"https://api.github.com/repos/{REPOSITORY}"


class GithubReleaseClient:
    """Small authenticated REST client; gh streams large assets."""

    def __init__(self, token):
        if not token:
            raise UploadError("GITHUB_TOKEN is required for image release upload")
        self.token = token

    def request(self, method, path, payload=None, missing_ok=False):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            API_ROOT + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise UploadError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
        except (OSError, ValueError) as error:
            raise UploadError(f"GitHub API {method} {path} did not return valid JSON") from error

    def get_tag(self, tag):
        encoded = urllib.parse.quote(tag, safe="")
        return self.request("GET", f"/git/ref/tags/{encoded}", missing_ok=True)

    def get_release_by_tag(self, tag):
        encoded = urllib.parse.quote(tag, safe="")
        return self.request("GET", f"/releases/tags/{encoded}", missing_ok=True)

    def create_draft(self, tag, sha, reference):
        return self.request("POST", "/releases", {
            "tag_name": tag,
            "target_commitish": sha,
            "name": reference,
            "body": "Signed, provenance-attested pack image release assets.",
            "draft": True,
            "prerelease": False,
            "make_latest": "false",
        })

    def get_release(self, release_id):
        return self.request("GET", f"/releases/{release_id}")

    def publish(self, release_id):
        return self.request("PATCH", f"/releases/{release_id}", {"draft": False})

    def gh(self, args):
        environment = os.environ.copy()
        environment["GH_TOKEN"] = self.token
        try:
            subprocess.run(
                ["gh", *args, "--repo", REPOSITORY],
                check=True, capture_output=True, timeout=1800, env=environment,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise UploadError("GitHub release asset transfer failed") from error

    def upload(self, tag, assets):
        self.gh(["release", "upload", tag, *(str(asset) for asset in assets)])

    def download(self, tag, directory):
        self.gh(["release", "download", tag, "--dir", str(directory)])


def require_release(release, tag, sha, reference, draft, assets=None):
    if (not isinstance(release, dict)
            or type(release.get("id")) is not int
            or release.get("draft") is not draft
            or release.get("tag_name") != tag
            or release.get("target_commitish") != sha
            or release.get("name") != reference):
        raise UploadError("draft release identity differs from the verified source")
    if assets is not None:
        published = release.get("assets")
        if (not isinstance(published, list)
                or len(published) != len(assets)
                or {item.get("name") for item in published if isinstance(item, dict)}
                    != set(assets)):
            raise UploadError("release asset set differs from staged assets")
        for item in published:
            if (not isinstance(item, dict)
                    or item.get("size") != assets[item["name"]]["size"]
                    or item.get("state", "uploaded") != "uploaded"):
                raise UploadError("release asset metadata differs from staged bytes")
            digest = item.get("digest")
            if digest is not None and digest != f"sha256:{assets[item['name']]['sha256']}":
                raise UploadError("release asset digest differs from staged bytes")
    return release["id"]


def tag_points_to(tag_ref, sha):
    if not isinstance(tag_ref, dict):
        return False
    obj = tag_ref.get("object")
    return (isinstance(obj, dict)
            and obj.get("type") == "commit"
            and obj.get("sha") == sha)


def staged_assets(staged):
    staged = Path(staged)
    if (not stat.S_ISDIR(staged.lstat().st_mode)
            or {entry.name for entry in staged.iterdir()} != ASSET_NAMES
            or any(not stat.S_ISREG(entry.lstat().st_mode) for entry in staged.iterdir())):
        raise UploadError("staged release has missing, linked or extra assets")
    assets = {name: stager.record(staged / name) for name in ASSET_NAMES}
    if any(value["size"] <= 0 for value in assets.values()):
        raise UploadError("staged release contains an empty asset")
    return staged, assets


def verify_download(client, tag, assets):
    with tempfile.TemporaryDirectory(prefix="mvm-pack-downloaded-", dir="/tmp") as temporary:
        downloaded = Path(temporary)
        client.download(tag, downloaded)
        if {entry.name for entry in downloaded.iterdir()} != ASSET_NAMES:
            raise UploadError("downloaded asset set differs from staged release")
        for name, expected_asset in assets.items():
            path = downloaded / name
            if (not stat.S_ISREG(path.lstat().st_mode)
                    or stager.record(path) != expected_asset):
                raise UploadError(f"downloaded asset {name} differs from staged bytes")


def release_identity(descriptor, reference, environment):
    try:
        signer.check_identity(environment)
    except signer.SigningError as error:
        raise UploadError(str(error)) from error
    tag = descriptor["release"]["tag"]
    expected = f"pack-{reference.partition('@')[0].replace('/', '-')}-v{reference.partition('@')[2]}"
    if (descriptor["release"] != {"repository": REPOSITORY, "tag": expected}
            or tag != expected):
        raise UploadError("release tag differs from the exact pack reference")
    return tag, environment["GITHUB_SHA"]


def publish_verified(staged, descriptor, reference, environment, client):
    tag, sha = release_identity(descriptor, reference, environment)
    staged, assets = staged_assets(staged)
    tag_ref = client.get_tag(tag)
    existing = client.get_release_by_tag(tag)
    if (tag_ref is None) != (existing is None):
        raise UploadError("incomplete existing release cannot be resumed")
    if existing is None:
        draft = client.create_draft(tag, sha, reference)
        release_id = require_release(draft, tag, sha, reference, True)
        client.upload(tag, [staged / name for name in sorted(ASSET_NAMES)])
    else:
        if type(existing.get("draft")) is not bool:
            raise UploadError("existing release draft state is invalid")
        release_id = require_release(existing, tag, sha, reference,
                                     existing["draft"], assets)
        verify_download(client, tag, assets)
        if not tag_points_to(tag_ref, sha):
            raise UploadError("existing release tag does not point to the verified source commit")
        if not existing["draft"]:
            published = client.get_release(release_id)
            require_release(published, tag, sha, reference, False, assets)
            if not tag_points_to(client.get_tag(tag), sha):
                raise UploadError("published release tag does not point to the verified source commit")
            return published
    draft = client.get_release(release_id)
    require_release(draft, tag, sha, reference, True, assets)
    verify_download(client, tag, assets)
    tag_ref = client.get_tag(tag)
    if not tag_points_to(tag_ref, sha):
        raise UploadError("release tag does not point to the verified source commit")
    client.publish(release_id)
    published = client.get_release(release_id)
    require_release(published, tag, sha, reference, False, assets)
    published_tag = client.get_tag(tag)
    if not tag_points_to(published_tag, sha):
        raise UploadError("published release tag does not point to the verified source commit")
    return published


def verify_published(staged, descriptor, reference, environment, client):
    """Recheck an existing public release before signing a registry manifest."""
    tag, sha = release_identity(descriptor, reference, environment)
    _, assets = staged_assets(staged)
    release = client.get_release_by_tag(tag)
    require_release(release, tag, sha, reference, False, assets)
    verify_download(client, tag, assets)
    if not tag_points_to(client.get_tag(tag), sha):
        raise UploadError("published release tag does not point to the verified source commit")
    return release


def verify_public_image(descriptor, reference, client):
    """Authenticate the published release without relying on producer staging."""
    builder = helper("build-packs.py", "build_packs_public_image_verify")
    try:
        builder.validate_built_image_descriptor(descriptor, reference)
    except SystemExit as error:
        raise UploadError("published image descriptor is invalid") from error
    tag = descriptor["release"]["tag"]
    with tempfile.TemporaryDirectory(prefix="mvm-pack-public-", dir="/tmp") as temporary:
        downloaded = Path(temporary)
        client.download(tag, downloaded)
        if {entry.name for entry in downloaded.iterdir()} != ASSET_NAMES:
            raise UploadError("published image asset set has missing or extra files")
        if any(not stat.S_ISREG(entry.lstat().st_mode) for entry in downloaded.iterdir()):
            raise UploadError("published image contains a linked or special asset")
        try:
            released_descriptor = stager.read_json(downloaded / "image-descriptor.json")
        except stager.StageError as error:
            raise UploadError(str(error)) from error
        if released_descriptor != descriptor:
            raise UploadError("published descriptor differs from the signed manifest")
        for asset in descriptor["assets"].values():
            name = asset["name"]
            if asset != {"name": name, **stager.record(downloaded / name)}:
                raise UploadError(f"published image asset {name} differs from descriptor")
        try:
            signer.check_boot_sidecar(downloaded / "mvm-meta.json", reproducer)
        except signer.SigningError as error:
            raise UploadError(str(error)) from error
        try:
            provenance = stager.read_json(downloaded / "provenance.json")
        except stager.StageError as error:
            raise UploadError(str(error)) from error
        source_sha = verify_provenance(provenance, descriptor, reference)
        try:
            stager.verify_bundle(downloaded / "rootfs.ext4",
                                 downloaded / "rootfs.signature.json")
            stager.verify_bundle(downloaded / "provenance.json",
                                 downloaded / "provenance.signature.json")
        except stager.StageError as error:
            raise UploadError(str(error)) from error
        assets = {name: stager.record(downloaded / name) for name in ASSET_NAMES}
        release = client.get_release_by_tag(tag)
        require_release(release, tag, source_sha, reference, False, assets)
        if not tag_points_to(client.get_tag(tag), source_sha):
            raise UploadError("published image tag does not point to the attested source")
        require_release(client.get_release(release["id"]), tag, source_sha,
                        reference, False, assets)
        return source_sha


def verify_provenance(statement, descriptor, reference):
    """Require the signed statement to bind image, base, workflow and source."""
    try:
        subject = statement["subject"]
        predicate = statement["predicate"]
        definition = predicate["buildDefinition"]
        dependencies = definition["resolvedDependencies"]
        details = predicate["runDetails"]
        invocation = details["metadata"]["invocationId"]
        builder_id = details["builder"]["id"]
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise UploadError("published image provenance is incomplete") from error
    base = descriptor["base_set"]
    if (not isinstance(statement, dict)
            or set(statement) != {"_type", "subject", "predicateType", "predicate"}
            or statement["_type"] != "https://in-toto.io/Statement/v1"
            or statement["predicateType"] != "https://slsa.dev/provenance/v1"
            or subject != [{"name": "rootfs.ext4", "digest": {
                "sha256": descriptor["assets"]["rootfs"]["sha256"]}}]
            or not isinstance(definition, dict)
            or definition.get("buildType") != (
                "https://github.com/tinylabscom/mvm-packs/blob/main/"
                "README.packs.md#pack-image-composition-v1")
            or definition.get("externalParameters") != {
                "reference": reference, "base_set": base}
            or not isinstance(definition.get("internalParameters"), dict)
            or set(definition["internalParameters"]) != {"verifier_sha256"}
            or not isinstance(definition["internalParameters"]["verifier_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}",
                                definition["internalParameters"]["verifier_sha256"])
            or not isinstance(invocation, str)
            or not invocation.startswith(
                "https://github.com/tinylabscom/mvm-packs/actions/runs/")
            or builder_id != signer.PUBLISHER_IDENTITY
            or not isinstance(dependencies, list)
            or len(dependencies) != 5):
        raise UploadError("published image provenance does not bind its release")
    required = {
        "image-set.json": {"sha256": base["manifest_sha256"]},
    }
    found = {}
    source_sha = None
    for item in dependencies:
        if (not isinstance(item, dict) or set(item) != {"uri", "digest"}
                or not isinstance(item["uri"], str)
                or not isinstance(item["digest"], dict)
                or len(item["digest"]) != 1
                or item["uri"] in found):
            raise UploadError("published image provenance dependency is ambiguous")
        found[item["uri"]] = item["digest"]
        prefix = "git+https://github.com/tinylabscom/mvm-packs@"
        if item["uri"].startswith(prefix):
            source_sha = item["uri"][len(prefix):]
            if (not re.fullmatch(r"[0-9a-f]{40}", source_sha)
                    or item["digest"] != {"gitCommit": source_sha}):
                raise UploadError("published image source commit is invalid")
    if (source_sha is None
            or found.get("image-set.json") != required["image-set.json"]
            or set(found) != {
                "candidate.json", "application-layer/rootfs.ext4",
                "image-set.json", "mvm/images.lock",
                f"git+https://github.com/tinylabscom/mvm-packs@{source_sha}"}
            or any(not isinstance(found[uri].get("sha256"), str)
                   or not re.fullmatch(r"[0-9a-f]{64}", found[uri]["sha256"])
                   for uri in ("candidate.json", "application-layer/rootfs.ext4",
                               "mvm/images.lock"))):
        raise UploadError("published image provenance dependencies are invalid")
    return source_sha


def upload(evidence, reference, pack_source, images_lock, environment, client):
    with tempfile.TemporaryDirectory(prefix="mvm-pack-upload-", dir="/tmp") as temporary:
        staged = Path(temporary) / "staged"
        try:
            stager.stage(evidence, reference, pack_source, images_lock, staged)
        except stager.StageError as error:
            raise UploadError(str(error)) from error
        descriptor = stager.read_json(staged / "image-descriptor.json")
        return publish_verified(staged, descriptor, reference, environment, client)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--pack-source", required=True, type=Path)
    parser.add_argument("--mvm-images-lock", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        client = GithubReleaseClient(os.environ.get("GITHUB_TOKEN"))
        result = upload(args.evidence, args.reference, args.pack_source,
                        args.mvm_images_lock, os.environ, client)
        print(f"published verified image release {result['tag_name']}")
    except (OSError, KeyError, TypeError, ValueError, UploadError) as error:
        parser.exit(1, f"upload-image-release: {error}\n")


if __name__ == "__main__":
    main()
