#!/usr/bin/env python3
"""Build the signed pack registry layout under packs/.

Reads pack sources from pack-sources/<namespace>/<name>/:

    pack.toml          version = "semver", description = "..."
    pack/profile.toml  a policy profile (optional)
    pack/group.toml    a policy group (optional)

For every source pack, emits packs/<namespace>/<name>/<version>/ with:

    manifest.json             the signed RegistryPackManifest (mvm schema v1)
    manifest.sigstore.json    detached cosign bundle over manifest.json
    files/<path>              the payload, byte-identical to the source

and regenerates the root index.json with exact-byte manifest SHA-256 pins.
Refuses to overwrite an existing version with different bytes: pack
content is immutable once published, so a changed source needs a version
bump in its pack.toml.

The cosign bundle is produced by `cosign sign-blob` (keyless in the publish
workflow; a test key with COSIGN_KEY locally). The mvm client verifies the
bundle on every pull and on every policy load, against the publisher trust
policy.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path

import ed25519
import pack_details
import rootfs_requirements
from application_manifest import manifest_bytes as application_manifest_bytes
from application_manifest import unique_object, validate_application, validate_runtime_layer
from publisher_identity import (
    CURRENT_IDENTITY,
    PUBLISHER_ISSUER,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "pack-sources"
PACKS = ROOT / "packs"
DETAILS = ROOT / "pack-details"

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.+-]+)?$")
COORD = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BUILT_IMAGE_ASSETS = {
    "rootfs": "rootfs.ext4",
    "verity": "rootfs.verity",
    "roothash": "rootfs.roothash",
    "mvm_meta": "mvm-meta.json",
    "rootfs_signature_bundle": "rootfs.signature.json",
    "provenance_statement": "provenance.json",
    "provenance_signature_bundle": "provenance.signature.json",
}


def fail(message):
    sys.exit(f"pack build: {message}")


def parse_pack_toml(path):
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(path.read_text())
    version = data.get("version")
    description = data.get("description")
    if not isinstance(version, str) or not SEMVER.match(version):
        fail(f"{path}: version must be a strict semver string, got {version!r}")
    if not isinstance(description, str) or not description.strip():
        fail(f"{path}: description must be a non-empty string")
    # Generated pages put the description into Markdown, where html.escape does not
    # neutralise newlines or links.
    if any(not character.isprintable() for character in description) or "](" in description:
        fail(f"{path}: description must be one printable line without Markdown links")
    if set(data) - {"version", "description", "application", "requirements", "runtime_layer"}:
        fail(f"{path}: unknown pack metadata fields")
    if "runtime_layer" in data:
        if "application" in data or "requirements" in data:
            fail(f"{path}: a runtime layer cannot also declare application or requirements")
        try:
            validate_runtime_layer(data["runtime_layer"])
        except ValueError as error:
            fail(f"{path}: {error}")
    application = data.get("application")
    if "application" in data:
        try:
            validate_application(application)
        except ValueError as error:
            fail(f"{path}: {error}")
        if not SEMVER.fullmatch(version) or "+" in version:
            fail(f"{path}: application version must be canonical semver without build metadata")
    requirements = None
    if "requirements" in data:
        if "application" not in data:
            fail(f"{path}: [requirements] is only allowed on an application source")
        try:
            requirements = rootfs_requirements.validate_requirements(data["requirements"])
        except ValueError as error:
            fail(f"{path}: {error}")
    return {"version": version, "description": description, "application": application,
            "requirements": requirements, "runtime_layer": data.get("runtime_layer")}


def sha256_of(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def manifest_bytes(reference, description, payload):
    # The payload root itself is the `pack/` directory: its contents ship
    # under `pack/` in the manifest, the path mvm reads policy documents
    # from (pack/profile.toml, pack/group.toml).
    files = []
    for path in payload.rglob("*"):
        if path.is_symlink():
            fail(f"payload symlink is not allowed: {path.relative_to(payload)}")
    for path in sorted(p for p in payload.rglob("*") if p.is_file()):
        rel = "pack/" + path.relative_to(payload).as_posix()
        parts = rel.split("/")
        if rel.startswith("/") or ".." in parts or not all(parts):
            fail(f"unsafe payload path {rel!r}")
        sha256, size = sha256_of(path)
        files.append({"path": rel, "sha256": sha256, "size": size})
    manifest = {
        "schema_version": 1,
        "reference": reference,
        "description": description,
        "files": files,
    }
    return json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n", files


def verify_bundle(manifest_path, bundle_path, identity):
    if not bundle_path.is_file():
        return False
    result = subprocess.run(
        [
            "cosign", "verify-blob", str(manifest_path),
            "--bundle", str(bundle_path),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", PUBLISHER_ISSUER,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def check_existing_payload(out, payload):
    published = out / "files" / "pack"
    if any(path.is_symlink() for path in (out / "files").rglob("*")):
        fail(f"{out}: published payload contains a symlink")
    source_files = {p.relative_to(payload) for p in payload.rglob("*") if p.is_file()}
    published_files = {p.relative_to(published) for p in published.rglob("*") if p.is_file()}
    if source_files != published_files:
        fail(f"{out}: published payload file set differs from source")
    for relative in source_files:
        if (payload / relative).read_bytes() != (published / relative).read_bytes():
            fail(f"{out}: published payload differs from source at {relative}")


def bundle_key_url(source):
    """The bundle public key is published beside the archive: <stem>-bundle-publisher.pub."""
    if not source.startswith("https://") or not source.endswith(".mvmpkg"):
        fail(f"{source}: cannot locate the bundle public key beside a non-.mvmpkg source")
    return source[: -len(".mvmpkg")] + "-bundle-publisher.pub"


def require_public_host(url):
    """Refuse a fetch aimed at localhost or a non-public IP literal.

    shortcut: DNS names are not resolved here, so a name that points at a private
    address passes; upgrade by resolving and checking addresses at connect time.
    """
    host = (urlsplit(url).hostname or "").rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        fail(f"{url}: refusing to fetch from localhost")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        fail(f"{url}: refusing to fetch from a non-public address")


class PublicHttpsRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to public https hosts; urlopen would also follow http and ftp."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, "redirect to a non-HTTPS URL refused", headers, fp)
        require_public_host(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


urllib.request.install_opener(urllib.request.build_opener(PublicHttpsRedirects))


def fetch_bundle_key(bundle):
    """Download the 32-byte Ed25519 key and bind it to the descriptor's key_id.

    key_id is the first 32 hex characters of the key's SHA-256, so an author
    cannot supply a different key. Trusting that key stays with the consumer.
    """
    url = bundle_key_url(bundle["source"])
    require_public_host(url)
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            key = response.read(65)
    except OSError as error:
        fail(f"{url}: cannot read the bundle public key: {error}")
    if len(key) != 32 or hashlib.sha256(key).hexdigest()[:32] != bundle["key_id"]:
        fail(f"{url}: not a 32-byte key matching the descriptor key_id")
    return key


def check_environment_policy(manifest, expected, path):
    """The signed environment's policy must equal the declared one exactly: no missing request
    budget, no extra host, no other difference. A missing budget would leave the spend ceiling
    unenforced by admission."""
    environments = [m for m in manifest.get("members", []) if isinstance(m, dict) and m.get("class") == "environment"]
    if len(environments) != 1:
        fail(f"{path}: the bundle manifest must carry exactly one environment member")
    if environments[0].get("policy") != expected:
        fail(f"{path}: the signed environment policy does not equal the declared environment_policy")


def check_embedded_requirements(archive, member, requirements, path):
    """Copy the (already hash-checked) rootfs out of the tar and list it read-only."""
    with tempfile.NamedTemporaryFile(prefix="rootfs-") as image:
        source = archive.extractfile(member)
        while chunk := source.read(1 << 20):
            image.write(chunk)
        image.flush()
        try:
            rootfs_requirements.check_rootfs(image.name, requirements)
        except ValueError as error:
            fail(f"{path}: {error}")


def archive_details(manifest, application, requirements):
    """What the gate saw in the archive, for pack pages (see pack_details.py). Not signed."""
    bundle = application["bundle"]
    members = [m for m in manifest.get("members", []) if isinstance(m, dict)]
    environments = [m for m in members if m.get("class") == "environment"]
    environment = ({k: environments[0][k] for k in pack_details.ENV_KEYS if k in environments[0]}
                   if len(environments) == 1 else None)
    return {
        "schema_version": 1,
        "reference": None,
        "archive": {"sha256": bundle["archive_sha256"], "size": bundle["archive_size"],
                    "key_id": bundle["key_id"], "arch": application["guest_arch"]},
        "created_at": manifest.get("created_at") if isinstance(manifest.get("created_at"), str) else None,
        "artifacts": [{"name": str(a.get("name", a["path"])), "role": str(a["role"]),
                       "size_bytes": a["size_bytes"], "sha256": a["sha256"]} for a in manifest["artifacts"]],
        "runtime": [{"class": m["class"], "version": str(m["version"])} for m in members
                    if m.get("class") == "embedded_cli_boot_assets" and "version" in m],
        "environment": environment,
        "binaries": list((requirements or {}).get("binaries") or []),
    }


def write_details(namespace, name, version, details):
    """Record the details next to the published version. Informational: never blocks signing."""
    try:
        details = dict(details, reference=f"{namespace}/{name}@{version}")
        pack_details.validate(details)
        target = DETAILS / namespace / name / f"{version}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".tmp")
        partial.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        partial.replace(target)
        print(f"{namespace}/{name}@{version}: recorded archive details")
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"{namespace}/{name}@{version}: archive details not recorded: {error}")


def inspect_bundle(path, application, public_key, requirements=None):
    """Return the recorded archive details after refusing unless the archive embeds the application: a kernel and a root
    filesystem whose hashes match the bundle manifest, for the descriptor's
    key ID and architecture, with a valid Ed25519 manifest.sig by that key.
    Members are read, never extracted.

    A valid signature shows the archive is internally consistent under the key
    the descriptor names. It does not make that key trusted: the consumer decides.
    """
    bundle = application["bundle"]
    try:
        with tarfile.open(path, "r:") as archive:
            members = {}
            for info in archive:
                parts = info.name.split("/")
                if (info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or info.name in members
                        or info.name.startswith("/")
                        or ".." in parts or "" in parts):
                    fail(f"{path}: unsafe or duplicate archive member {info.name!r}")
                members[info.name] = info
            if "manifest.json" not in members or "manifest.sig" not in members:
                fail(f"{path}: archive has no manifest.json and manifest.sig")
            if members["manifest.sig"].size != 64 or members["manifest.json"].size > 1 << 20:
                fail(f"{path}: manifest.sig must be 64 bytes and manifest.json at most 1 MiB")
            manifest_raw = archive.extractfile("manifest.json").read()
            if not ed25519.verify(public_key, manifest_raw, archive.extractfile("manifest.sig").read()):
                fail(f"{path}: manifest.sig is not a valid signature by the descriptor's bundle key")
            manifest = json.loads(manifest_raw, object_pairs_hook=unique_object)
            if manifest.get("key_id") != bundle["key_id"] or manifest.get("arch") != application["guest_arch"]:
                fail(f"{path}: bundle key ID or architecture does not match the descriptor")
            artifacts = manifest.get("artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                fail(f"{path}: bundle manifest lists no artifacts")
            roles, hashed, rootfs_path = set(), set(), None
            for artifact in artifacts:
                if artifact["path"] in hashed:
                    fail(f"{path}: artifact {artifact['path']!r} is listed twice")
                hashed.add(artifact["path"])
                info = members.get(artifact["path"])
                if info is None or info.size != artifact["size_bytes"]:
                    fail(f"{path}: artifact {artifact['path']!r} is missing or has the wrong size")
                digest, handle = hashlib.sha256(), archive.extractfile(info)
                while chunk := handle.read(1 << 20):
                    digest.update(chunk)
                if digest.hexdigest() != artifact["sha256"]:
                    fail(f"{path}: artifact {artifact['path']!r} does not match its recorded SHA-256")
                roles.add(artifact["role"])
                if artifact["role"] == "rootfs":
                    if rootfs_path is not None:
                        fail(f"{path}: archive lists more than one root filesystem")
                    rootfs_path = artifact["path"]
            if sum(members[p].size for p in hashed) > bundle["archive_size"]:
                fail(f"{path}: artifacts are larger than the archive")
            if not {"kernel", "rootfs"} <= roles:
                fail(f"{path}: archive does not embed a kernel and a root filesystem")
            if requirements and requirements.get("environment_policy") is not None:
                check_environment_policy(manifest, requirements["environment_policy"], path)
            if requirements and rootfs_requirements.needs_rootfs(requirements):
                check_embedded_requirements(archive, members[rootfs_path], requirements, path)
            details = archive_details(manifest, application, requirements)
    except (tarfile.TarError, ValueError, KeyError, TypeError, AttributeError, OSError,
            RecursionError, MemoryError) as error:
        fail(f"{path}: not a valid application archive: {error!r}")
    return details


def _measure_file(path):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _cached_archive(bundle):
    """Path of a previously downloaded copy that still matches the descriptor, else None.

    The cache only saves a download. A cached file is re-hashed every time and a copy that
    does not match the pinned SHA-256 and size is deleted, so trust never rests on the cache.
    """
    directory = os.environ.get("MVM_ARCHIVE_CACHE")
    if not directory:
        return None
    path = Path(directory) / f"{bundle['archive_sha256']}.mvmpkg"
    if not path.is_file() or path.is_symlink():
        return None
    sha256, size = _measure_file(path)
    if sha256 == bundle["archive_sha256"] and size == bundle["archive_size"]:
        return path
    path.unlink(missing_ok=True)
    return None


def _store_in_cache(bundle, spooled):
    """Keep a verified download for later runs. Never fatal: a cache failure only costs time."""
    directory = os.environ.get("MVM_ARCHIVE_CACHE")
    if not directory:
        return
    try:
        target = Path(directory) / f"{bundle['archive_sha256']}.mvmpkg"
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".partial")
        shutil.copyfile(spooled, partial)
        partial.replace(target)
    except OSError as error:
        print(f"archive cache: not stored: {error}")


# urlopen's timeout is per socket read, so a drip-feeding source needs this overall bound.
DOWNLOAD_DEADLINE_SECONDS = 15 * 60


def verify_archive(application, requirements=None):
    """Read the pinned archive back before signing a new application version.

    Refuses unless size and SHA-256 match the descriptor and the archive embeds
    the application and carries a valid bundle signature (inspect_bundle). Runs only for
    new versions (ADR 001). With MVM_ARCHIVE_CACHE set, a digest-named copy of an earlier
    verified download is reused after being re-hashed.
    """
    bundle = application["bundle"]
    source = bundle["source"]
    if not source.startswith("https://"):
        fail(f"{source}: only HTTPS archive sources can be read back before signing")
    require_public_host(source)
    public_key = fetch_bundle_key(bundle)
    cached = _cached_archive(bundle)
    if cached is not None:
        print(f"archive cache: using {cached.name} (re-verified)")
        return inspect_bundle(str(cached), application, public_key, requirements)
    digest, size = hashlib.sha256(), 0
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    with tempfile.NamedTemporaryFile(prefix="mvmpkg-") as spool:
        try:
            with urllib.request.urlopen(source, timeout=60) as response:
                while chunk := response.read(1 << 20):
                    if time.monotonic() > deadline:
                        fail(f"{source}: archive download exceeded {DOWNLOAD_DEADLINE_SECONDS} seconds")
                    size += len(chunk)
                    if size > bundle["archive_size"]:
                        break
                    digest.update(chunk)
                    spool.write(chunk)
        except OSError as error:
            fail(f"{source}: cannot read the archive back: {error}")
        if size != bundle["archive_size"]:
            fail(f"{source}: archive size does not match the descriptor")
        if digest.hexdigest() != bundle["archive_sha256"]:
            fail(f"{source}: archive SHA-256 does not match the descriptor")
        spool.flush()
        details = inspect_bundle(spool.name, application, public_key, requirements)
        _store_in_cache(bundle, spool.name)
        return details


def sign(manifest_path, bundle_path):
    cmd = ["cosign", "sign-blob", "--yes"]
    key = os.environ.get("COSIGN_KEY")
    if key:
        cmd += ["--key", key]
    cmd += ["--bundle", str(bundle_path), str(manifest_path)]
    subprocess.run(cmd, check=True)


def build_one(source, check_only=False):
    namespace, name = source.parent.name, source.name
    if not COORD.match(namespace) or not COORD.match(name):
        fail(f"{source}: namespace/name must match {COORD.pattern}")
    meta = parse_pack_toml(source / "pack.toml")
    reference = f"{namespace}/{name}@{meta['version']}"
    if meta["runtime_layer"] is not None:
        fail(f"{reference}: runtime layers are not publishable until the mvm consumer dispatch, installer and our gate exist (ADR 005)")
    application = meta["application"]
    payload = source / "pack"
    if application is not None:
        if any(path.name != "pack.toml" or path.is_symlink() for path in source.iterdir()):
            fail(f"{source}: application source cannot contain payload files or directories")
    elif not payload.is_dir():
        fail(f"{source}: missing pack/ payload directory")
    out = PACKS / namespace / name / meta["version"]
    if application is not None:
        manifest = application_manifest_bytes(reference, meta["description"], application)
    else:
        manifest, _ = manifest_bytes(reference, meta["description"], payload)

    if out.exists():
        existing = (out / "manifest.json").read_bytes()
        if existing != manifest:
            fail(
                f"{reference}: version already published with different bytes; "
                "bump the version in pack.toml"
            )
        if application is not None:
            if any(
                path.is_symlink() or not path.is_file()
                or path.name not in {"manifest.json", "manifest.sigstore.json"}
                for path in out.iterdir()
            ):
                fail(f"{out}: application cannot contain payload files or directories")
        else:
            check_existing_payload(out, payload)
        if check_only:
            print(f"{reference}: source valid")
            return
        bundle = out / "manifest.sigstore.json"
        if verify_bundle(out / "manifest.json", bundle, CURRENT_IDENTITY):
            print(f"{reference}: unchanged")
            return
        fail(f"{reference}: existing signature is not trusted; refusing to re-sign")

    if application is None and not out.exists():
        fail(
            f"{reference}: a pack must embed its application binary in the .mvmpkg; "
            "policy-only versions cannot be published or signed (add an [application] bundle)"
        )
    if check_only:
        print(f"{reference}: source valid")
        return

    details = verify_archive(application, meta["requirements"]) if application is not None else None
    tmp = out.with_name(out.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    if application is None:
        (tmp / "files").mkdir()
        files_root = tmp / "files" / "pack"
        for path in payload.rglob("*"):
            if path.is_file():
                target = files_root / path.relative_to(payload)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    (tmp / "manifest.json").write_bytes(manifest)
    sign(tmp / "manifest.json", tmp / "manifest.sigstore.json")
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    if details is not None:
        write_details(namespace, name, meta["version"], details)
    print(f"{reference}: published")


def version_key(value):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", value)
    return [int(part) for part in match.groups()] if match else [0, 0, 0]


def registry_index(packs_dir):
    """Derive discovery metadata only from published manifests, not sources."""
    packs = []
    if packs_dir.is_dir():
        for namespace in sorted(p for p in packs_dir.iterdir() if p.is_dir()):
            for name in sorted(p for p in namespace.iterdir() if p.is_dir()):
                versions = sorted(
                    (
                        p.name
                        for p in name.iterdir()
                        if p.is_dir() and (p / "manifest.json").is_file()
                    ),
                    key=version_key,
                    reverse=True,
                )
                if versions:
                    manifest = json.loads(
                        (name / versions[0] / "manifest.json").read_text()
                    )
                    packs.append(
                        {
                            "namespace": namespace.name,
                            "name": name.name,
                            "description": manifest["description"],
                            "versions": [
                                {
                                    "version": version,
                                    "manifest_sha256": sha256_of(
                                        name / version / "manifest.json"
                                    )[0],
                                }
                                for version in versions
                            ],
                        }
                    )
    return {"schema_version": 2, "packs": packs}


def rebuild_index():
    index = registry_index(PACKS)
    encoded = json.dumps(index, indent=2) + "\n"
    PACKS.mkdir(exist_ok=True)
    (PACKS.parent / "index.json").write_text(encoded)
    print(f"index: {len(index['packs'])} pack(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-sources", action="store_true",
                        help="validate sources and version immutability without signing or writing")
    args = parser.parse_args()
    if not SOURCES.is_dir():
        fail("pack-sources/ does not exist")
    sources = sorted(
        p for p in SOURCES.glob("*/*") if p.is_dir() and (p / "pack.toml").is_file()
    )
    if not sources:
        fail("no pack sources under pack-sources/<namespace>/<name>/")
    for source in sources:
        build_one(source, check_only=args.check_sources)
    if not args.check_sources:
        rebuild_index()


if __name__ == "__main__":
    main()
