import io
import tarfile
import tempfile
import unittest
from pathlib import Path

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
