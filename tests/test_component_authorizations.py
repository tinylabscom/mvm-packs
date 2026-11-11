import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder  # noqa: F401, sets sys.path
import component_authorizations as auth

REF, SHA = "agent/demo@1.0.0", "a" * 64


def entry(ref=REF, sha=SHA, extra=""):
    return f'[[approved]]\nreference = "{ref}"\narchive_sha256 = "{sha}"\napproved_by = "o"\ndate = "2026-11-11"\n{extra}'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "auth.toml"

    def check(self, text):
        self.path.write_text(text)
        return auth.component_authorized(REF, SHA, self.path)


class AuthorizationFile(Base):
    def test_empty_file_authorizes_nothing(self):
        self.assertFalse(self.check("approved = []\n"))
        self.assertFalse(auth.component_authorized(REF, SHA))  # the shipped file

    def test_exact_reference_and_hash_authorize(self):
        self.assertTrue(self.check(entry()))

    def test_changed_hash_is_refused(self):
        self.assertFalse(self.check(entry(sha="b" * 64)))

    def test_changed_reference_is_refused(self):
        self.assertFalse(self.check(entry(ref="agent/demo@1.0.1")))

    def test_malformed_file_never_authorizes(self):
        for text in ("approved = [", entry(extra="x = 1\n"), entry().replace("date", "when"),
                     entry() + entry(), entry(sha="A" * 64), entry(sha="a" * 63), "other = 1\n" + entry()):
            with self.subTest(text=text), self.assertRaises(Exception):
                self.check(text)

    def test_missing_file_authorizes_nothing(self):
        self.assertFalse(auth.component_authorized(REF, SHA, self.dir / "none.toml"))


class BuildGate(Base):
    def source(self, kind="application_component"):
        namespace = "agent" if kind == "application_component" else kind.removesuffix("_component")
        source = self.dir / "pack-sources" / namespace / "demo"
        source.mkdir(parents=True)
        extra = ('[[application_component.entrypoints]]\nname = "default"\nargv = ["/bin/demo"]\n'
                 if kind == "application_component" else "dependencies = []\n")
        (source / "pack.toml").write_text(
            f'version = "1.0.0"\ndescription = "demo"\n[{kind}]\nschema_version = 1\nguest_arch = "aarch64"\n{extra}'
            f'[{kind}.archive]\nsource = "https://example.com/a.tar"\narchive_sha256 = "{SHA}"\narchive_size = 1\n'
            f'[{kind}.requirements]\nfilesystem_abi = 1\nlibc = "musl"\nloader = "/lib/ld-musl-aarch64.so.1"\n'
            'minimum_kernel = "6.1.0"\nrequired_capabilities = []\n')
        return source

    def test_build_packs_refuses_before_signing(self):
        source = self.source()
        with patch.object(builder, "sign") as sign, patch.object(builder, "COMPONENT_AUTHORIZATIONS", self.path):
            with self.assertRaisesRegex(SystemExit, "component not authorized by the owner"):
                builder.build_one(source)
        sign.assert_not_called()

    def test_check_sources_validates_components_without_failing(self):
        for kind in ("application_component", "runtime_component", "tool_component"):
            source = self.source(kind)
            out = io.StringIO()
            with patch.object(builder, "sign") as sign, patch.object(builder, "COMPONENT_AUTHORIZATIONS", self.path), \
                    redirect_stdout(out):
                builder.build_one(source, check_only=True)
            sign.assert_not_called()
            self.assertIn("not authorized for signing", out.getvalue())

    def test_authorized_component_still_needs_the_payload_gate(self):
        source = self.source()
        self.path.write_text(entry(ref="agent/demo@1.0.0"))
        with patch.object(builder, "sign") as sign, patch.object(builder, "COMPONENT_AUTHORIZATIONS", self.path), \
                patch.object(builder, "verify_component_archive", side_effect=SystemExit("payload bad")) as gate:
            with self.assertRaisesRegex(SystemExit, "payload bad"):
                builder.build_one(source)
        gate.assert_called_once()
        sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
