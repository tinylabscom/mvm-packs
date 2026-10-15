"""Contract-only adversarial tests; no released client, VM or real signatures."""

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "protected-observer-v2.py"
spec = importlib.util.spec_from_file_location("protected_observer_v2_tests", SCRIPT)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def record(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def source():
    return {
        "repository": "tinylabscom/mvm-packs",
        "ref": "refs/heads/main",
        "sha": "c" * 40,
        "workflow_ref": "tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
        "run_id": "1234",
        "run_attempt": "2",
        "invocation": "https://github.com/tinylabscom/mvm-packs/actions/runs/1234/attempts/2",
        "publisher_identity": "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
    }


class StrictJSONTests(unittest.TestCase):
    def test_duplicate_keys_at_every_depth_refuse(self):
        for raw in (
            b'{"schema_version":2,"schema_version":1}',
            b'{"source":{"sha":"a","sha":"b"}}',
            b'{"modes":{"persistent":{"observations":{"exit":0,"exit":0}}}}',
            b'{"inventory":{"a":{"size":1,"size":true}}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(observer.WitnessError):
                observer.parse_json(raw)

    def test_nonfinite_and_invalid_json_refuse(self):
        for raw in (
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":-Infinity}',
            b'{"value":0,}',
            b'{"value":"\xff"}',
        ):
            with self.subTest(raw=raw), self.assertRaises(observer.WitnessError):
                observer.parse_json(raw)

    def test_parser_does_not_coerce_numeric_types(self):
        parsed = observer.parse_json(b'{"integer":2,"boolean":true,"float":2.0}')
        self.assertIs(type(parsed["integer"]), int)
        self.assertIs(type(parsed["boolean"]), bool)
        self.assertIs(type(parsed["float"]), float)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ReportAndPolicyTests(unittest.TestCase):
    """Structural fixtures only: records here do not authenticate real assets."""

    def setUp(self):
        self.source = source()
        self.environment = {
            "GITHUB_" + key.upper(): self.source[key]
            for key in (
                "repository",
                "ref",
                "sha",
                "workflow_ref",
                "run_id",
                "run_attempt",
            )
        }
        self.pin = "a" * 64
        self.document = {
            "schema_version": 2,
            "role": "protected-observer",
            "backend": "unit-mock",
            "version": 1,
        }
        self.policy_raw = encode(self.document)
        entry = {
            "path": observer.POLICY_PATH,
            "role": "protected-observer",
            "backend": "unit-mock",
            "version": 1,
            "document": record(self.policy_raw),
        }
        self.registry = {"schema_version": 2, "policies": [entry]}
        self.registry_raw = encode(self.registry)
        self.report = {
            "schema_version": 2,
            "kind": "protected-observer-diagnostic",
            "source": self.source,
            "reference": "runtime/python@1.1.0",
            "producer_sha256": self.pin,
            "clients": {role: self.client(role) for role in ("A", "B")},
            "candidate": {
                "manifest": record(b"UNIT-MANIFEST"),
                "bundle": record(b"UNIT-BUNDLE"),
                "verifier_sha256": self.pin,
                "payload": {"pack/group.toml": record(b"UNIT")},
            },
            "policy": {
                **entry,
                "source": self.source,
                "registry": record(self.registry_raw),
            },
            "artifacts": {
                mode: record(("UNIT-" + mode).encode())
                for mode in ("transient", "persistent")
            },
        }
        self.policies = {
            (
                observer.POLICY_PATH,
                "protected-observer",
                "unit-mock",
                1,
                self.source["repository"],
                self.source["ref"],
                self.source["sha"],
                self.source["workflow_ref"],
                record(self.policy_raw)["sha256"],
            ): self.policy_raw
        }

    def client(self, role):
        tag = "v0.24.0" if role == "A" else "v0.24.1"
        return {
            "repository": "tinylabscom/mvm",
            "tag": tag,
            "platform": "linux/x86_64",
            "archive_name": "mvmctl-x86_64-unknown-linux-gnu.tar.gz",
            "member": "mvmctl-x86_64-unknown-linux-gnu/mvmctl",
            "observed_source": {
                "repository": "tinylabscom/mvm",
                "ref": "refs/tags/" + tag,
                "sha": "b" * 40,
            },
            **{
                key: record((role + key).encode())
                for key in (
                    "archive",
                    "checksums",
                    "archive_bundle",
                    "checksums_bundle",
                )
            },
            "executable": {
                "sha256": self.pin if role == "A" else "b" * 64,
                "size": 100,
            },
        }

    def validate(self, **kwargs):
        arguments = {
            "environment": self.environment,
            "checkout_sha": self.source["sha"],
            "workflow_sha": self.source["sha"],
            "trusted_registry": self.registry_raw,
            "producer_sha256": self.pin,
        }
        arguments.update(kwargs)
        return observer.validate_report(self.report, self.policies, **arguments)

    def test_diagnostic_roundtrip_never_authorizes_publication(self):
        self.assertEqual(self.validate(), self.document)
        self.assertFalse(observer.INTEGRATION_ENABLED)
        with self.assertRaisesRegex(observer.WitnessError, "integration disabled"):
            observer.require_publication_authorization(self.report)

    def test_v1_hybrid_default_roles_and_bool_version_refuse(self):
        for field, bad in (
            ("schema_version", 1),
            ("schema_version", True),
            ("schema_version", 2.0),
            ("kind", "observed-publication-witness"),
            ("client", self.report["clients"]["A"]),
            ("role", "default"),
        ):
            original = copy.deepcopy(self.report)
            self.report[field] = bad
            with (
                self.subTest(field=field, bad=bad),
                self.assertRaises(observer.WitnessError),
            ):
                self.validate()
            self.report = original

    def test_every_closed_envelope_rejects_missing_and_extra_fields(self):
        paths = [
            (),
            ("source",),
            ("clients",),
            ("candidate",),
            ("policy",),
            ("artifacts",),
            ("candidate", "manifest"),
            ("candidate", "bundle"),
            ("policy", "document"),
            ("policy", "registry"),
            ("candidate", "payload", "pack/group.toml"),
        ]
        for role in ("A", "B"):
            paths += [("clients", role), ("clients", role, "observed_source")]
            paths += [
                ("clients", role, key)
                for key in (
                    "archive",
                    "checksums",
                    "archive_bundle",
                    "checksums_bundle",
                    "executable",
                )
            ]
        original = copy.deepcopy(self.report)
        for path in paths:
            target = original
            for key in path:
                target = target[key]
            for removed in (*target, None):
                self.report = copy.deepcopy(original)
                edited = self.report
                for key in path:
                    edited = edited[key]
                if removed is None:
                    edited["unknown"] = "AUTHOR"
                else:
                    del edited[removed]
                with (
                    self.subTest(path=path, removed=removed),
                    self.assertRaises(observer.WitnessError),
                ):
                    self.validate()
        self.report = original

    def test_global_pin_none_and_wrong_pin_refuse(self):
        for pin in (None, "b" * 64, self.report["clients"]["A"]["archive"]["sha256"]):
            with self.subTest(pin=pin), self.assertRaises(observer.WitnessError):
                self.validate(producer_sha256=pin)

    def test_a_b_independence_and_candidate_h_refuse(self):
        original = copy.deepcopy(self.report)
        for section, key, bad in (
            ("B", "tag", self.report["clients"]["A"]["tag"]),
            ("B", "archive", self.report["clients"]["A"]["archive"]),
            ("B", "executable", self.report["clients"]["A"]["executable"]),
            ("candidate", "verifier_sha256", "b" * 64),
        ):
            self.report = copy.deepcopy(original)
            target = (
                self.report["candidate"]
                if section == "candidate"
                else self.report["clients"][section]
            )
            target[key] = bad
            with (
                self.subTest(section=section, key=key),
                self.assertRaises(observer.WitnessError),
            ):
                self.validate()

    def test_run_attempt_checkout_and_workflow_replay_refuse(self):
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"):
            environment = dict(self.environment)
            environment[key] = "d" * 40 if key.endswith("SHA") else "9"
            with self.subTest(key=key), self.assertRaises(observer.WitnessError):
                self.validate(environment=environment)
        for key in ("checkout_sha", "workflow_sha"):
            with self.subTest(key=key), self.assertRaises(observer.WitnessError):
                self.validate(**{key: "d" * 40})

    def test_registry_bytes_selected_document_and_duplicate_selector_refuse(self):
        with self.assertRaises(observer.WitnessError):
            self.validate(trusted_registry=self.registry_raw + b"\n")
        for mutation in ("document", "unknown", "duplicate", "bool"):
            registry = copy.deepcopy(self.registry)
            if mutation == "document":
                registry["policies"][0]["document"] = record(b"OTHER")
            elif mutation == "unknown":
                registry["author_verdict"] = True
            elif mutation == "duplicate":
                registry["policies"].append(copy.deepcopy(registry["policies"][0]))
            else:
                registry["policies"][0]["version"] = True
            raw = encode(registry)
            self.report["policy"]["registry"] = record(raw)
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(observer.WitnessError),
            ):
                self.validate(trusted_registry=raw)

    def test_policy_document_closed_nested_types_and_no_report_policy_bytes(self):
        original = dict(self.policies)
        key = next(iter(self.policies))
        for bad in (
            b'{"schema_version":2,"schema_version":2}',
            encode({**self.document, "expected_success": True}),
            encode({**self.document, "version": True}),
        ):
            self.policies = {**original, key: bad}
            with self.subTest(bad=bad), self.assertRaises(observer.WitnessError):
                self.validate()


class ClientByteBindingTests(unittest.TestCase):
    """Actual local tar/checksum bytes; all cosign cryptography is mocked."""

    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.directory = Path(temporary).resolve()
        self.executable = (
            b"\x7fELF\x02\x01"
            + b"\x00" * 12
            + b"\x3e\x00"
            + b"UNIT-ONLY-NOT-A-RELEASED-EXECUTABLE"
        )
        self.archive_name = "mvmctl-x86_64-unknown-linux-gnu.tar.gz"
        self.member = "mvmctl-x86_64-unknown-linux-gnu/mvmctl"
        self.client = {
            "repository": "tinylabscom/mvm",
            "tag": "v0.24.0",
            "platform": "linux/x86_64",
            "archive_name": self.archive_name,
            "member": self.member,
            "observed_source": {
                "repository": "tinylabscom/mvm",
                "ref": "refs/tags/v0.24.0",
                "sha": "a" * 40,
            },
            "executable": record(self.executable),
        }
        self.write_archive()

    def write_archive(self, *, member=None, kind=tarfile.REGTYPE, duplicate=False):
        path = self.directory / self.archive_name
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo(member or self.member)
            entry.mode = 0o755
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = len(self.executable)
                archive.addfile(entry, io.BytesIO(self.executable))
                if duplicate:
                    archive.addfile(entry, io.BytesIO(self.executable))
            else:
                entry.linkname = self.member
                archive.addfile(entry)
        self.client["archive"] = record(path.read_bytes())
        self.write_checksums()
        for role, name in (
            ("archive_bundle", self.archive_name + ".bundle"),
            ("checksums_bundle", "checksums-sha256.txt.bundle"),
        ):
            raw = ("UNIT-ONLY-SIGNATURE:" + role).encode()
            (self.directory / name).write_bytes(raw)
            self.client[role] = record(raw)

    def write_checksums(self, text=None):
        if text is None:
            text = self.client["archive"]["sha256"] + "  " + self.archive_name + "\n"
        raw = text.encode()
        (self.directory / "checksums-sha256.txt").write_bytes(raw)
        self.client["checksums"] = record(raw)

    def verify(self):
        with mock.patch.object(observer.subprocess, "run") as signature:
            observer.verify_client(self.client, self.directory, source=source())
            return signature

    def test_exact_archive_member_and_both_signed_subjects(self):
        signature = self.verify()
        self.assertEqual(signature.call_count, 2)
        commands = [call.args[0] for call in signature.call_args_list]
        for command in commands:
            self.assertIn(
                "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.24.0",
                command,
            )
            self.assertIn("https://token.actions.githubusercontent.com", command)
        subjects = {Path(command[2]).name for command in commands}
        self.assertEqual(subjects, {self.archive_name, "checksums-sha256.txt"})

    def test_signature_failure_and_timeout_refuse(self):
        for error in (
            subprocess.CalledProcessError(1, "cosign"),
            subprocess.TimeoutExpired("cosign", 300),
            FileNotFoundError("cosign unavailable"),
        ):
            with (
                self.subTest(error=error),
                mock.patch.object(observer.subprocess, "run", side_effect=error),
                self.assertRaises(observer.WitnessError),
            ):
                observer.verify_client(self.client, self.directory, source=source())

    def test_role_and_subject_substitution_refuse_before_crypto(self):
        for role in (
            "candidate",
            "image-evidence",
            "report",
            "default",
            "legacy",
            "release-checksums",
        ):
            with (
                self.subTest(role=role),
                mock.patch.object(observer.subprocess, "run") as crypto,
            ):
                with self.assertRaises(observer.WitnessError):
                    observer.verify_signature(
                        self.directory / self.archive_name,
                        self.directory / (self.archive_name + ".bundle"),
                        role=role,
                        source=source(),
                        tag=self.client["tag"],
                    )
                crypto.assert_not_called()

    def test_checksum_must_uniquely_name_exact_archive(self):
        digest = self.client["archive"]["sha256"]
        for text in (
            f"{digest}  other.tar.gz\n",
            f"{digest}  {self.archive_name}\n{digest}  {self.archive_name}\n",
            f"{'0' * 64}  {self.archive_name}\n",
            f"{digest}  ./{self.archive_name}\n",
        ):
            with self.subTest(text=text):
                self.write_checksums(text)
                with self.assertRaises(observer.WitnessError):
                    self.verify()

    def test_archive_alias_link_and_duplicate_members_refuse(self):
        for member, kind, duplicate in (
            ("../" + self.member, tarfile.REGTYPE, False),
            ("./" + self.member, tarfile.REGTYPE, False),
            (self.member, tarfile.SYMTYPE, False),
            (self.member, tarfile.LNKTYPE, False),
            (self.member, tarfile.REGTYPE, True),
        ):
            with self.subTest(member=member, kind=kind, duplicate=duplicate):
                self.write_archive(member=member, kind=kind, duplicate=duplicate)
                with self.assertRaises(observer.WitnessError):
                    self.verify()

    def test_loose_executable_digest_is_not_archive_membership(self):
        self.client["executable"] = record(b"OTHER-EXECUTABLE")
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_extended_metadata_is_rejected_before_reading_its_body(self):
        for kind in (
            tarfile.XHDTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        ):
            entry = tarfile.TarInfo("UNIT-EXTENDED-METADATA")
            entry.type, entry.size = kind, 1 << 30
            raw = gzip.compress(entry.tobuf(format=tarfile.USTAR_FORMAT))
            (self.directory / self.archive_name).write_bytes(raw)
            self.client["archive"] = record(raw)
            self.write_checksums()
            requests = []
            original = gzip.GzipFile.read

            def traced(stream, size=-1):
                requests.append(size)
                return original(stream, size)

            with (
                self.subTest(kind=kind),
                mock.patch.object(observer.gzip.GzipFile, "read", traced),
                self.assertRaisesRegex(observer.WitnessError, "extended"),
            ):
                self.verify()
            self.assertEqual(requests, [512])

    def test_bundle_swap_refuses_before_crypto_can_mask_mismatch(self):
        first = self.directory / (self.archive_name + ".bundle")
        second = self.directory / "checksums-sha256.txt.bundle"
        a, b = first.read_bytes(), second.read_bytes()
        first.write_bytes(b)
        second.write_bytes(a)
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_symlink_and_hardlink_inputs_refuse(self):
        path = self.directory / "checksums-sha256.txt"
        raw = path.read_bytes()
        path.unlink()
        other = self.directory / "other"
        other.write_bytes(raw)
        for link in ("symlink", "hardlink"):
            with self.subTest(link=link):
                if link == "symlink":
                    path.symlink_to(other)
                else:
                    os.link(other, path)
                try:
                    with self.assertRaises(observer.WitnessError):
                        self.verify()
                finally:
                    path.unlink()

    def test_client_closed_shape_and_boolean_size_refuse(self):
        original = copy.deepcopy(self.client)
        variants = []
        for key in original:
            value = copy.deepcopy(original)
            del value[key]
            variants.append(value)
        for key, bad in (("role", "producer"), ("platform", "linux/aarch64")):
            value = copy.deepcopy(original)
            value[key] = bad
            variants.append(value)
        value = copy.deepcopy(original)
        value["archive"]["size"] = True
        variants.append(value)
        for value in variants:
            with self.subTest(client=value), self.assertRaises(observer.WitnessError):
                self.client = value
                self.verify()


class CandidateByteBindingTests(unittest.TestCase):
    """Canonical publisher output with mocked signatures, never admission."""

    def setUp(self):
        from tests.test_private_image_candidate import PrivateEvidenceTests

        self.fixture = PrivateEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        private, (_, _), _ = self.fixture.prepare()
        self.directory = (private / "registry").resolve()
        # This fixture is byte-validation only. Its original aarch64 image is
        # relabelled for the first proposed diagnostic lane, NOT executed.
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["image"]["platform"] = "linux/x86_64"
        path.write_text(json.dumps(manifest))
        (self.directory / "manifest.sigstore.json").write_bytes(b"UNIT-ONLY-BUNDLE")
        provenance = json.loads(
            (self.directory / "files" / "provenance.json").read_bytes()
        )
        self.pin = provenance["predicate"]["buildDefinition"]["internalParameters"][
            "verifier_sha256"
        ]
        self.rebind()

    def rebind(self):
        self.candidate = {
            "manifest": record((self.directory / "manifest.json").read_bytes()),
            "bundle": record((self.directory / "manifest.sigstore.json").read_bytes()),
            "verifier_sha256": self.pin,
            "payload": {
                path.relative_to(self.directory / "files").as_posix(): record(
                    path.read_bytes()
                )
                for path in (self.directory / "files").rglob("*")
                if path.is_file()
            },
        }

    def verify(self):
        with mock.patch.object(observer.subprocess, "run") as signature:
            observer.verify_candidate(
                self.candidate,
                self.directory,
                source=source(),
                reference="runtime/python@1.1.0",
            )
            return signature

    def test_canonical_publisher_inventory_and_exact_manifest_subject(self):
        signature = self.verify()
        self.assertGreaterEqual(signature.call_count, 1)
        commands = [call.args[0] for call in signature.call_args_list]
        manifest = [
            command for command in commands if Path(command[2]).name == "manifest.json"
        ]
        self.assertEqual(len(manifest), 1)
        self.assertIn(source()["publisher_identity"], manifest[0])
        for option, value in (
            ("--certificate-github-workflow-repository", source()["repository"]),
            ("--certificate-github-workflow-ref", source()["ref"]),
            ("--certificate-github-workflow-sha", source()["sha"]),
        ):
            self.assertEqual(manifest[0][manifest[0].index(option) + 1], value)

    def test_inventory_missing_extra_and_changed_bytes_refuse(self):
        path = self.directory / "files" / "pack" / "group.toml"
        raw = path.read_bytes()
        for change in ("missing", "extra", "changed"):
            with self.subTest(change=change):
                if change == "missing":
                    path.unlink()
                elif change == "extra":
                    (self.directory / "files" / "extra").write_bytes(b"EXTRA")
                else:
                    path.write_bytes(b"CHANGED")
                try:
                    with self.assertRaises(observer.WitnessError):
                        self.verify()
                finally:
                    path.write_bytes(raw)
                    (self.directory / "files" / "extra").unlink(missing_ok=True)

    def test_rehashed_outer_record_cannot_hide_duplicate_manifest_keys(self):
        path = self.directory / "manifest.json"
        raw = path.read_bytes()
        path.write_bytes(b'{"schema_version":1,' + raw.lstrip()[1:])
        self.candidate["manifest"] = record(path.read_bytes())
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_rehashed_payload_cannot_override_manifest_inventory(self):
        path = self.directory / "files" / "pack" / "group.toml"
        path.write_bytes(b"AUTHOR-SUPPLIED-REPLACEMENT")
        self.rebind()
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_payload_path_aliases_refuse(self):
        original = copy.deepcopy(self.candidate)
        for alias in (
            "./pack/group.toml",
            "pack//group.toml",
            "pack/../pack/group.toml",
            "/pack/group.toml",
            "pack\\group.toml",
        ):
            self.candidate = copy.deepcopy(original)
            self.candidate["payload"][alias] = self.candidate["payload"].pop(
                "pack/group.toml"
            )
            with self.subTest(alias=alias), self.assertRaises(observer.WitnessError):
                self.verify()

    def test_symlink_hardlink_and_empty_extra_directory_refuse(self):
        path = self.directory / "files" / "pack" / "group.toml"
        raw = path.read_bytes()
        other = self.directory.parent / "other-policy"
        other.write_bytes(raw)
        path.unlink()
        for link in ("symlink", "hardlink"):
            with self.subTest(link=link):
                if link == "symlink":
                    path.symlink_to(other)
                else:
                    os.link(other, path)
                try:
                    with self.assertRaises(observer.WitnessError):
                        self.verify()
                finally:
                    path.unlink()
        path.write_bytes(raw)
        (self.directory / "files" / "empty-extra").mkdir()
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_verifier_pin_must_match_provenance_not_claimed_field(self):
        self.candidate["verifier_sha256"] = "0" * 64
        with self.assertRaises(observer.WitnessError):
            self.verify()

    def test_rehashed_provenance_must_bind_subject_reference_base_source_and_run(self):
        provenance_path = self.directory / "files" / "provenance.json"
        original = json.loads(provenance_path.read_bytes())
        manifest_path = self.directory / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for mutation in (
            "subject",
            "reference",
            "base",
            "source",
            "run",
            "builder",
            "unknown",
        ):
            value = copy.deepcopy(original)
            definition = value["predicate"]["buildDefinition"]
            if mutation == "subject":
                value["subject"][0]["digest"]["sha256"] = "0" * 64
            elif mutation == "reference":
                definition["externalParameters"]["reference"] = "runtime/python@9.9.9"
            elif mutation == "base":
                definition["externalParameters"]["base_set"]["manifest_sha256"] = (
                    "0" * 64
                )
            elif mutation == "source":
                definition["resolvedDependencies"][-1]["digest"]["gitCommit"] = "0" * 40
            elif mutation == "run":
                value["predicate"]["runDetails"]["metadata"]["invocationId"] += "9"
            elif mutation == "builder":
                value["predicate"]["runDetails"]["builder"]["id"] = "OTHER-PUBLISHER"
            else:
                value["author_verdict"] = True
            raw = encode(value)
            provenance_path.write_bytes(raw)
            manifest["image"]["assets"]["provenance_statement"].update(record(raw))
            manifest_path.write_bytes(encode(manifest))
            self.rebind()
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(observer.WitnessError),
            ):
                self.verify()

    def test_empty_canonical_policy_file_is_valid_byte_inventory(self):
        path = self.directory / "files" / "pack" / "group.toml"
        path.write_bytes(b"")
        manifest_path = self.directory / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for entry in manifest["files"]:
            if entry["path"] == "pack/group.toml":
                entry.update(record(b""))
        manifest_path.write_bytes(encode(manifest))
        self.rebind()
        self.verify()

    def test_invalid_reference_and_empty_description_refuse(self):
        for reference in (None, "invalid", "runtime/python@latest"):
            with (
                self.subTest(reference=reference),
                self.assertRaises(observer.WitnessError),
            ):
                observer.verify_candidate(
                    self.candidate,
                    self.directory,
                    source=source(),
                    reference=reference,
                )
        manifest_path = self.directory / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["description"] = "  "
        manifest_path.write_bytes(encode(manifest))
        self.rebind()
        with self.assertRaises(observer.WitnessError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
