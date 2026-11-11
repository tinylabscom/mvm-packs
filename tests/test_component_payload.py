import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_publisher_verification import builder  # noqa: F401, sets sys.path
from application_manifest import inspect_component_payload


def payload(*members):
    """members: (name, type, data/linkname, mode)"""
    handle = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    with tarfile.open(fileobj=handle, mode="w:") as archive:
        for name, kind, data, mode in members:
            info = tarfile.TarInfo(name)
            info.type, info.mode = kind, mode
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                info.linkname = data if kind == tarfile.SYMTYPE else ""
                archive.addfile(info)
    handle.close()
    return handle.name


def reg(name, data=b"x", mode=0o644):
    return (name, tarfile.REGTYPE, data, mode)


class ComponentPayloadTests(unittest.TestCase):
    def check(self, *members, kind="runtime_component", **kw):
        path = payload(*members)
        self.addCleanup(Path(path).unlink)
        return inspect_component_payload(path, kind, **kw)

    def test_refuses_absolute_and_dotdot_paths(self):
        for name in ("/etc/passwd", "usr/../../x"):
            with self.assertRaisesRegex(ValueError, "path"):
                self.check(reg(name))

    def test_refuses_escaping_symlink(self):
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.check(reg("a"), ("l", tarfile.SYMTYPE, "../../etc", 0o777))
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.check(reg("a"), ("l", tarfile.SYMTYPE, "/etc", 0o777))
        self.check(reg("bin/a"), ("bin/l", tarfile.SYMTYPE, "a", 0o777))

    def test_refuses_device_fifo_and_setuid(self):
        for kind in (tarfile.CHRTYPE, tarfile.FIFOTYPE):
            with self.assertRaisesRegex(ValueError, "only files"):
                self.check(reg("a"), ("d", kind, "", 0o644))
        for mode in (0o4755, 0o2755):
            with self.assertRaisesRegex(ValueError, "setuid"):
                self.check(reg("a", mode=mode))

    def test_refuses_size_zero_and_over_cap(self):
        with self.assertRaisesRegex(ValueError, "no file content"):
            self.check(reg("a", b""))
        with self.assertRaisesRegex(ValueError, "cap"):
            self.check(reg("a", b"xxxx"), max_bytes=3)

    def test_application_paths_must_be_under_srv_app(self):
        with self.assertRaisesRegex(ValueError, "srv/app"):
            self.check(reg("usr/bin/x"), kind="application_component")
        self.assertEqual(self.check(reg("srv/app/x"), kind="application_component"), {"files": 1, "bytes": 1})

    def test_accepts_a_clean_payload(self):
        result = self.check(("usr", tarfile.DIRTYPE, "", 0o755), reg("usr/a", b"ab"), reg("usr/b", b"c"))
        self.assertEqual(result, {"files": 2, "bytes": 3})
        self.assertEqual(self.check(reg("usr/a"), kind="tool_component")["files"], 1)

    def test_refuses_symlink_chain_escape(self):
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.check(reg("d/f"), ("d/l1", tarfile.SYMTYPE, "..", 0o777),
                       ("d/l1/l2", tarfile.SYMTYPE, "../etc", 0o777))

    def test_refuses_writes_through_symlinks(self):
        with self.assertRaisesRegex(ValueError, "srv/app"):
            self.check(("srv/app", tarfile.SYMTYPE, "..", 0o777), reg("srv/app/usr/bin/sh"),
                       kind="application_component")
        with self.assertRaisesRegex(ValueError, "through"):
            self.check(reg("a"), ("l", tarfile.SYMTYPE, "a", 0o777), reg("l/z"))

    def test_application_symlink_must_stay_under_srv_app(self):
        with self.assertRaisesRegex(ValueError, "srv/app"):
            self.check(("srv/app/bin", tarfile.SYMTYPE, "../../usr/bin", 0o777), reg("srv/app/x"),
                       kind="application_component")

    def test_refuses_duplicate_names(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check(reg("a"), ("a", tarfile.SYMTYPE, "b", 0o777))

    def sym(self, name, target):
        return (name, tarfile.SYMTYPE, target, 0o777)

    def test_probe_dot_prefix_and_dot_components_are_refused(self):
        app = "application_component"
        cases = [  # p06, p14, p07, p05, p08, p16
            ([reg("a/f"), self.sym("l", "a"), reg("./l/z")], "runtime_component"),
            ([self.sym("srv/app/l", "."), reg("srv/app/./l/z")], app),
            ([reg("a"), reg("./a")], "runtime_component"),
            ([self.sym("./l", "..")], "runtime_component"),
            ([self.sym("a//l", "../..")], "runtime_component"),
            ([self.sym("d/.", "..")], "runtime_component"),
        ]
        for members, kind in cases:
            with self.subTest(members=[m[0] for m in members]), self.assertRaises(ValueError):
                self.check(reg("a/keep"), *members, kind=kind)

    def test_stale_link_targets_are_refused(self):
        # p11 and p12: a later link turns an ancestor of an earlier target into a symlink
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.check(self.sym("x", "b/b2/c"), self.sym("b", "."), self.sym("z", "x/../../.."))
        with self.assertRaisesRegex(ValueError, "srv/app"):
            self.check(self.sym("srv/app/x", "b/b2/c"), self.sym("srv/app/b", "."),
                       self.sym("srv/app/z", "x/../../.."), kind="application_component")

    def test_symlink_loop_is_refused(self):
        with self.assertRaisesRegex(ValueError, "loop"):
            self.check(self.sym("a", "b"), self.sym("b", "a"))


class VerifyComponentArchiveTests(unittest.TestCase):
    def run_verify(self, tar_members, kind="runtime_component", clock=None, **changes):
        path = payload(*tar_members)
        self.addCleanup(Path(path).unlink)
        data = Path(path).read_bytes()
        archive = {"source": "https://bundles.example/c.tar", "archive_sha256": hashlib.sha256(data).hexdigest(),
                   "archive_size": len(data)} | changes
        fetched = self.fetched = []

        def serve(url, timeout=None):
            fetched.append(url)
            return io.BytesIO(data)

        patches = [patch.object(builder.urllib.request, "urlopen", side_effect=serve)]
        if clock:
            patches.append(patch.object(builder.time, "monotonic", side_effect=clock))
        with patches[0]:
            if clock:
                with patches[1]:
                    result = builder.verify_component_archive({"archive": archive}, kind)
            else:
                result = builder.verify_component_archive({"archive": archive}, kind)
        return result, fetched

    def test_clean_archive_passes(self):
        result, _ = self.run_verify([reg("usr/a")])
        self.assertEqual(result, {"files": 1, "bytes": 1})

    def test_escaping_payload_in_pinned_archive_is_refused(self):
        with self.assertRaises(SystemExit):
            self.run_verify([reg("/etc/x")])

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(SystemExit):
            self.run_verify([reg("a")], archive_sha256="0" * 64)

    def test_bad_scheme_and_private_host_are_refused_before_fetch(self):
        for source in ("http://bundles.example/c.tar", "https://127.0.0.1/c.tar", "https://localhost/c.tar"):
            with self.subTest(source=source), self.assertRaises(SystemExit):
                try:
                    self.run_verify([reg("a")], source=source)
                finally:
                    self.assertEqual(self.fetched, [])

    def test_declared_size_zero_or_over_cap_is_refused(self):
        for size in (0, 2 * 1024**3 + 1):
            with self.subTest(size=size), self.assertRaises(SystemExit):
                self.run_verify([reg("a")], archive_size=size)

    def test_deadline_is_enforced(self):
        clock = iter([0])
        with self.assertRaisesRegex(SystemExit, "exceeded"):
            self.run_verify([reg("a")], clock=lambda: next(clock, builder.DOWNLOAD_DEADLINE_SECONDS + 1))
