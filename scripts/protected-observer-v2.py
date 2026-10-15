#!/usr/bin/env python3
"""Diagnostic PS-06 byte bindings, NOT a producer or publication capability.

Integration is disabled. No receipt wire schema or authenticated VM measurement
semantics are invented here. The policy registry selects protected diagnostic
documents only; it does not define runtime acceptance policy.
"""

import gzip
import importlib.util
import io
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "observer_v1", Path(__file__).with_name("observed-publication-witness.py")
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("required v1 helper unavailable")
v1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v1)
WitnessError = v1.WitnessError
parse_json = v1.parse_json
file_record = v1.file_record
bounded_bytes = v1.bounded_bytes
source_identity = v1.source_identity
shape = v1.shape
digest = v1.digest
LIMIT = v1.LIMIT
INTEGRATION_ENABLED = False
POLICY_PATH = ".github/policies/protected-observer-v2.json"
ARCHIVE = "mvmctl-x86_64-unknown-linux-gnu.tar.gz"
MEMBER = "mvmctl-x86_64-unknown-linux-gnu/mvmctl"
PUBLISHER = "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
SIGNATURE_ROLES = {
    "release-archive": "release",
    "release-checksums": "release",
    "image-evidence": PUBLISHER,
    "candidate": PUBLISHER,
    "report": PUBLISHER,
}
REPORT_FIELDS = {
    "schema_version",
    "kind",
    "source",
    "reference",
    "clients",
    "producer_sha256",
    "candidate",
    "policy",
    "artifacts",
}
CLIENT_FIELDS = {
    "repository",
    "tag",
    "platform",
    "archive_name",
    "member",
    "observed_source",
    "archive",
    "checksums",
    "archive_bundle",
    "checksums_bundle",
    "executable",
}


def _hex(value, length=64):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
        raise WitnessError("invalid full lowercase digest")


def _source(value):
    shape(
        value,
        {
            "repository",
            "ref",
            "sha",
            "workflow_ref",
            "run_id",
            "run_attempt",
            "invocation",
            "publisher_identity",
        },
        "source",
    )
    env = {
        f"GITHUB_{k.upper()}": value[k]
        for k in ("repository", "ref", "sha", "workflow_ref", "run_id", "run_attempt")
    }
    if not v1.exact(value, source_identity(env)):
        raise WitnessError("source/run/attempt differs")
    _hex(value["sha"], 40)


def _path(value):
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or any(ord(c) < 32 for c in value)
        or any(p in ("", ".", "..") for p in value.split("/"))
    ):
        raise WitnessError("noncanonical payload path")
    return value


def _inventory(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 256:
        raise WitnessError("invalid bounded inventory")
    for path, record in value.items():
        _path(path)
        file_record(record, empty=True, limit=256 << 20)


def _client(value):
    shape(value, CLIENT_FIELDS, "client")
    if (
        value["repository"] != "tinylabscom/mvm"
        or not isinstance(value["tag"], str)
        or not re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", value["tag"]
        )
        or value["platform"] != "linux/x86_64"
        or value["archive_name"] != ARCHIVE
        or value["member"] != MEMBER
    ):
        raise WitnessError("unsupported released Linux x86_64 client")
    observed = value["observed_source"]
    shape(observed, {"repository", "ref", "sha"}, "unsigned observed source")
    if (
        observed["repository"] != value["repository"]
        or observed["ref"] != "refs/tags/" + value["tag"]
    ):
        raise WitnessError("observed release context differs")
    _hex(observed["sha"], 40)
    for role in (
        "archive",
        "checksums",
        "archive_bundle",
        "checksums_bundle",
        "executable",
    ):
        file_record(value[role], limit=256 << 20)


def resolve_policy(binding, trusted_policies, *, source, trusted_registry):
    """Select exact documents from independently supplied protected registry bytes.

    Both trusted inputs must originate in the same checked-out protected source,
    never the report/candidate/dispatch. The registry has no runtime verdicts.
    """
    shape(
        binding,
        {"path", "role", "backend", "version", "source", "document", "registry"},
        "policy",
    )
    _source(source)
    if (
        binding["path"] != POLICY_PATH
        or binding["role"] != "protected-observer"
        or not isinstance(binding["backend"], str)
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", binding["backend"])
        or type(binding["version"]) is not int
        or binding["version"] < 1
        or not v1.exact(binding["source"], source)
    ):
        raise WitnessError("policy selection/source differs")
    file_record(binding["document"], limit=LIMIT)
    file_record(binding["registry"], limit=LIMIT)
    if (
        not isinstance(trusted_registry, bytes)
        or not 0 < len(trusted_registry) <= LIMIT
        or digest(trusted_registry) != binding["registry"]
    ):
        raise WitnessError("protected registry bytes differ")
    registry = parse_json(trusted_registry)
    shape(registry, {"schema_version", "policies"}, "protected registry")
    if (
        type(registry["schema_version"]) is not int
        or registry["schema_version"] != 2
        or not isinstance(registry["policies"], list)
        or not 1 <= len(registry["policies"]) <= 64
    ):
        raise WitnessError("invalid protected registry")
    selected, seen = None, set()
    for entry in registry["policies"]:
        shape(
            entry, {"path", "role", "backend", "version", "document"}, "registry entry"
        )
        if (
            entry["path"] != POLICY_PATH
            or entry["role"] != "protected-observer"
            or not isinstance(entry["backend"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", entry["backend"])
            or type(entry["version"]) is not int
            or entry["version"] < 1
        ):
            raise WitnessError("invalid protected registry entry")
        file_record(entry["document"], limit=LIMIT)
        selector = (entry["role"], entry["backend"], entry["version"])
        if selector in seen:
            raise WitnessError("duplicate registry selector")
        seen.add(selector)
        if selector == (binding["role"], binding["backend"], binding["version"]):
            selected = entry
    if selected is None or any(
        not v1.exact(selected[key], binding[key]) for key in selected
    ):
        raise WitnessError("selected policy differs from protected registry")
    key = (
        binding["path"],
        binding["role"],
        binding["backend"],
        binding["version"],
        source["repository"],
        source["ref"],
        source["sha"],
        source["workflow_ref"],
        binding["document"]["sha256"],
    )
    raw = trusted_policies.get(key)
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= LIMIT
        or digest(raw) != binding["document"]
    ):
        raise WitnessError("unknown protected policy bytes")
    policy = parse_json(raw)
    shape(policy, {"schema_version", "role", "backend", "version"}, "policy document")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 2
        or type(policy["version"]) is not int
        or any(policy[k] != binding[k] for k in ("role", "backend", "version"))
    ):
        raise WitnessError("unsupported policy selector")
    return policy


def validate_report(
    report,
    trusted_policies,
    *,
    environment,
    checkout_sha,
    workflow_sha,
    trusted_registry,
    producer_sha256=None,
):
    """Structural diagnostic only, requiring a caller-owned H executable pin."""
    shape(report, REPORT_FIELDS, "report")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 2
        or report["kind"] != "protected-observer-diagnostic"
    ):
        raise WitnessError("unsupported diagnostic schema")
    _source(report["source"])
    if (
        not v1.exact(report["source"], source_identity(environment))
        or checkout_sha != report["source"]["sha"]
        or workflow_sha != checkout_sha
    ):
        raise WitnessError("checkout/workflow/source/run/attempt differs")
    if not isinstance(report["reference"], str) or not v1.signer.REFERENCE.fullmatch(
        report["reference"]
    ):
        raise WitnessError("invalid reference")
    _hex(producer_sha256)
    _hex(report["producer_sha256"])
    shape(report["clients"], {"A", "B"}, "clients")
    for client in report["clients"].values():
        _client(client)
    a, b = report["clients"]["A"], report["clients"]["B"]
    if (
        report["producer_sha256"] != producer_sha256
        or a["executable"]["sha256"] != producer_sha256
        or b["executable"]["sha256"] == producer_sha256
        or a["archive"]["sha256"] == b["archive"]["sha256"]
        or a["tag"] == b["tag"]
    ):
        raise WitnessError("A/B/H independence or trusted pin differs")
    candidate = report["candidate"]
    shape(candidate, {"manifest", "bundle", "verifier_sha256", "payload"}, "candidate")
    for key in ("manifest", "bundle"):
        file_record(candidate[key], limit=LIMIT)
    _hex(candidate["verifier_sha256"])
    if candidate["verifier_sha256"] != producer_sha256:
        raise WitnessError("candidate verifier is not H")
    _inventory(candidate["payload"])
    shape(report["artifacts"], {"transient", "persistent"}, "opaque artifacts")
    for record in report["artifacts"].values():
        file_record(record, limit=LIMIT)
    return resolve_policy(
        report["policy"],
        trusted_policies,
        source=report["source"],
        trusted_registry=trusted_registry,
    )


def verify_signature(blob, bundle, *, role, source, tag=None):
    """Fixed role identities, never caller-selected certificate identities."""
    _source(source)
    if not isinstance(role, str) or role not in SIGNATURE_ROLES:
        raise WitnessError("unknown signature role")
    subjects = {
        "release-archive": (ARCHIVE, ARCHIVE + ".bundle"),
        "release-checksums": ("checksums-sha256.txt", "checksums-sha256.txt.bundle"),
        "candidate": ("manifest.json", "manifest.sigstore.json"),
    }
    if role not in subjects:
        raise WitnessError(
            "signature role requires an unimplemented integrated verifier"
        )
    if (Path(blob).name, Path(bundle).name) != subjects[role]:
        raise WitnessError("signature role/subject differs")
    if role == "candidate":
        manifest = parse_json(bounded_bytes(blob))
        shape(
            manifest,
            {"schema_version", "reference", "description", "files", "image"},
            "candidate signature subject",
        )
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
        ):
            raise WitnessError("signature role/subject schema differs")
    identity, args = SIGNATURE_ROLES[role], []
    if identity == "release":
        if not isinstance(tag, str) or not re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag
        ):
            raise WitnessError("invalid release tag")
        identity = f"https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/{tag}"
    else:
        args = [
            "--certificate-github-workflow-repository",
            source["repository"],
            "--certificate-github-workflow-ref",
            source["ref"],
            "--certificate-github-workflow-sha",
            source["sha"],
        ]
    try:
        subprocess.run(
            [
                "cosign",
                "verify-blob",
                str(blob),
                "--bundle",
                str(bundle),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                *args,
            ],
            check=True,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WitnessError("signature verification failed") from error


def verify_client(client, directory, *, source):
    """Authenticate snapshots; return exact executable bytes without running."""
    _client(client)
    names = {
        "archive": ARCHIVE,
        "archive_bundle": ARCHIVE + ".bundle",
        "checksums": "checksums-sha256.txt",
        "checksums_bundle": "checksums-sha256.txt.bundle",
    }
    directory = Path(directory)
    if {p.name for p in directory.iterdir()} != set(names.values()):
        raise WitnessError("client directory has extra/missing files")
    with tempfile.TemporaryDirectory() as temporary:
        snapshot, blobs = Path(temporary).resolve(), {}
        for role, name in names.items():
            raw = bounded_bytes(directory / name, limit=256 << 20)
            if digest(raw) != client[role]:
                raise WitnessError("client bytes differ")
            blobs[role] = raw
            (snapshot / name).write_bytes(raw)
        for role, signature in (
            ("archive", "archive_bundle"),
            ("checksums", "checksums_bundle"),
        ):
            verify_signature(
                snapshot / names[role],
                snapshot / names[signature],
                role="release-" + role,
                source=source,
                tag=client["tag"],
            )
        try:
            lines = blobs["checksums"].decode("ascii").splitlines()
        except UnicodeError as error:
            raise WitnessError("non-ASCII checksums") from error
        matches = []
        for line in lines:
            match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^ \t]+)", line)
            if match is None:
                raise WitnessError("malformed checksum line")
            if match[2] == ARCHIVE:
                matches.append(match[1])
        if matches != [client["archive"]["sha256"]]:
            raise WitnessError("archive checksum absent/duplicate/different")
        executable = None
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(blobs["archive"])) as archive:
                # Parse fixed-size headers BEFORE any extended metadata body.
                # TarFile iteration would consume PAX/GNU bodies before yielding.
                seen = set()
                while True:
                    header = archive.read(512)
                    if header == bytes(512):
                        trailer = archive.read(10241)
                        if len(trailer) < 512 or len(trailer) > 10240 or any(trailer):
                            raise WitnessError("invalid/bounded archive trailer")
                        break
                    if len(header) != 512 or len(seen) >= 2:
                        raise WitnessError("truncated/extra archive member")
                    member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                    if member.name in seen or member.type not in (
                        tarfile.REGTYPE,
                        tarfile.AREGTYPE,
                        tarfile.DIRTYPE,
                    ):
                        raise WitnessError("duplicate/extended/linked archive member")
                    seen.add(member.name)
                    if (
                        member.name == MEMBER
                        and member.isfile()
                        and member.mode & 0o111
                    ):
                        if (
                            member.size != client["executable"]["size"]
                            or member.size > 256 << 20
                        ):
                            raise WitnessError("archive executable size differs")
                        executable = archive.read(member.size)
                        padding = archive.read((-member.size) % 512)
                        if (
                            len(executable) != member.size
                            or len(padding) != (-member.size) % 512
                            or any(padding)
                        ):
                            raise WitnessError("truncated/noncanonical executable data")
                    elif (
                        member.name == MEMBER.rsplit("/", 1)[0]
                        and member.isdir()
                        and member.size == 0
                    ):
                        continue
                    else:
                        raise WitnessError("unsafe/extra archive member")
        except (tarfile.TarError, OSError, EOFError, UnicodeError) as error:
            raise WitnessError("invalid executable archive") from error
        if executable is None or digest(executable) != client["executable"]:
            raise WitnessError("executable bytes differ")
        if (
            len(executable) < 20
            or executable[:6] != b"\x7fELF\x02\x01"
            or executable[18:20] != b"\x3e\x00"
        ):
            raise WitnessError("executable is not x86_64 ELF")
        return executable


def verify_candidate(candidate, directory, *, source, reference):
    """Verify canonical publisher manifest and exact local transport inventory."""
    _source(source)
    if not isinstance(reference, str) or not v1.signer.REFERENCE.fullmatch(reference):
        raise WitnessError("invalid exact candidate reference")
    shape(candidate, {"manifest", "bundle", "verifier_sha256", "payload"}, "candidate")
    _hex(candidate["verifier_sha256"])
    _inventory(candidate["payload"])
    directory = Path(directory)
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary).resolve()
        for key, name in (
            ("manifest", "manifest.json"),
            ("bundle", "manifest.sigstore.json"),
        ):
            file_record(candidate[key], limit=LIMIT)
            raw = bounded_bytes(directory / name)
            if digest(raw) != candidate[key]:
                raise WitnessError("candidate manifest/bundle differs")
            (snapshot / name).write_bytes(raw)
        manifest = parse_json((snapshot / "manifest.json").read_bytes())
        shape(
            manifest,
            {"schema_version", "reference", "description", "files", "image"},
            "manifest",
        )
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["reference"] != reference
            or not isinstance(manifest["description"], str)
            or not manifest["description"].strip()
            or not isinstance(manifest["files"], list)
            or len(manifest["files"]) > 256
        ):
            raise WitnessError("unsupported canonical manifest")
        image = manifest["image"]
        shape(
            image,
            {"schema_version", "platform", "base_set", "release", "assets"},
            "image",
        )
        if type(image["schema_version"]) is not int or image["schema_version"] != 2:
            raise WitnessError("unsupported strict image schema")
        builder = v1.helper("build-packs.py", "observer_builder")
        try:
            builder.validate_built_image_descriptor(image, reference)
        except SystemExit as error:
            raise WitnessError("invalid image descriptor") from error
        if image["platform"] != "linux/x86_64":
            raise WitnessError("candidate platform differs")
        expected = {}
        for record in manifest["files"]:
            shape(record, {"path", "sha256", "size"}, "manifest file")
            path = _path(record["path"])
            if not path.startswith("pack/") or path in expected:
                raise WitnessError("duplicate/non-pack manifest path")
            expected[path] = {k: record[k] for k in ("sha256", "size")}
        for asset in image["assets"].values():
            path = _path(asset["name"])
            if path in expected:
                raise WitnessError("asset aliases manifest file")
            expected[path] = {k: asset[k] for k in ("sha256", "size")}
        _inventory(expected)
        if not v1.exact(expected, candidate["payload"]):
            raise WitnessError("canonical candidate inventory differs")
        required = {"manifest.json", "manifest.sigstore.json"}
        required.update("files/" + path for path in expected)
        directories = {"files"}
        for path in required:
            parent = Path(path).parent
            while str(parent) != ".":
                directories.add(parent.as_posix())
                parent = parent.parent
        found = set()
        for path in directory.rglob("*"):
            rel, info = path.relative_to(directory).as_posix(), path.lstat()
            if stat.S_ISDIR(info.st_mode) and rel in directories:
                continue
            if not stat.S_ISREG(info.st_mode) or rel not in required:
                raise WitnessError("extra/linked/special candidate entry")
            found.add(rel)
        if found != required:
            raise WitnessError("missing candidate bytes")
        provenance = None
        for path, record in expected.items():
            raw = bounded_bytes(directory / "files" / path, empty=True, limit=256 << 20)
            if digest(raw) != record:
                raise WitnessError("candidate payload bytes differ")
            if path == "provenance.json":
                provenance = parse_json(raw)
        try:
            definition = provenance["predicate"]["buildDefinition"]
            internal = definition["internalParameters"]
            dependencies = definition["resolvedDependencies"]
        except (TypeError, KeyError) as error:
            raise WitnessError(
                "candidate provenance has no verifier binding"
            ) from error
        shape(internal, {"verifier_sha256"}, "provenance verifier binding")
        if internal["verifier_sha256"] != candidate["verifier_sha256"]:
            raise WitnessError("candidate provenance verifier differs")
        if not isinstance(dependencies, list) or len(dependencies) != 5:
            raise WitnessError("invalid canonical provenance dependencies")
        by_uri = {}
        for dependency in dependencies:
            shape(dependency, {"uri", "digest"}, "provenance dependency")
            uri = dependency["uri"]
            if not isinstance(uri, str) or uri in by_uri:
                raise WitnessError("duplicate/invalid provenance dependency")
            by_uri[uri] = dependency["digest"]
        for uri in (
            "candidate.json",
            "application-layer/rootfs.ext4",
            "image-set.json",
            "mvm/images.lock",
        ):
            value = by_uri.get(uri)
            shape(value, {"sha256"}, "provenance dependency digest")
            _hex(value["sha256"])
        # Reuse the canonical publisher's existing statement constructor.
        # Candidate/layer/lock digests remain declared dependencies: they are
        # not independently verified inputs in this diagnostic API.
        composition = {
            "base_set": image["base_set"],
            "verifier_sha256": candidate["verifier_sha256"],
            "candidate_sha256": by_uri["candidate.json"]["sha256"],
            "application_layer_sha256": by_uri["application-layer/rootfs.ext4"][
                "sha256"
            ],
        }
        expected_provenance = v1.signer.provenance(
            reference,
            composition,
            expected["rootfs.ext4"],
            source["invocation"],
            source["sha"],
            by_uri["mvm/images.lock"]["sha256"],
        )
        if not v1.exact(provenance, expected_provenance):
            raise WitnessError("candidate provenance subject/base/source/run differs")
        verify_signature(
            snapshot / "manifest.json",
            snapshot / "manifest.sigstore.json",
            role="candidate",
            source=source,
        )
        return manifest


def require_publication_authorization(*args, **kwargs):
    raise WitnessError(
        "integration disabled: no reviewed immutable launch/session receipt adapter; "
        "diagnostic byte bindings cannot authorize producer or publication"
    )
