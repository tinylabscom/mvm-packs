"""verify() in compare-patched-elf.py against a small synthetic ELF and a simulated loader patch."""

import runpy
import struct
import unittest
from pathlib import Path

tool = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "compare-patched-elf.py"))
verify = tool["verify"]

EHDR, PHDR, SHDR, SYM = "<16sHHIQQQIHHHHHH", "<IIQQQQQQ", "<IIQQQQIIQQ", "<IBBHQQ"
IDENT = b"\x7fELF\x02\x01\x01" + b"\0" * 9
BASE, SHIFT = 0x400000, 0x1000
OLD_INTERP = b"/lib/ld-musl-aarch64.so.1\0"
NEW_INTERP = b"/nix/store/abc-musl-1.2.5/lib/ld-musl-aarch64.so.1\0"
SHSTR = b"\0.interp\0.text\0.dynsym\0.shstrtab\0"
NAMES = {".interp": 1, ".text": 9, ".dynsym": 15, ".shstrtab": 23}
TEXT = bytes((i * 7 + 3) & 0xFF for i in range(4096))


def layout():
    phdr_end = 64 + 4 * 56
    interp = phdr_end
    text = (interp + len(OLD_INTERP) + 7) & ~7
    dynsym = text + len(TEXT)
    shstr = dynsym + 3 * 24
    shdr = (shstr + len(SHSTR) + 7) & ~7
    return {"phdr_end": phdr_end, "interp": interp, "text": text, "dynsym": dynsym, "shstr": shstr, "shdr": shdr}


def section(name, kind, flags, addr, offset, size, link=0, info=0, align=1, entsize=0):
    return struct.pack(SHDR, NAMES.get(name, 0), kind, flags, addr, offset, size, link, info, align, entsize)


def build_upstream():
    lo = layout()
    out = bytearray(lo["shdr"])
    out[0:64] = struct.pack(EHDR, IDENT, 2, 183, 1, BASE + lo["text"], 64, lo["shdr"], 0, 64, 56, 4, 64, 5, 4)
    phdrs = [(6, 4, 64, BASE + 64, 224, 224, 8), (3, 4, lo["interp"], BASE + lo["interp"], len(OLD_INTERP), len(OLD_INTERP), 1),
             (1, 5, 0, BASE, lo["shstr"], lo["shstr"], 0x1000), (0x6474E551, 6, 0, 0, 0, 0x100000, 0)]
    for i, (t, f, o, v, fs, ms, al) in enumerate(phdrs):
        out[64 + i * 56:64 + (i + 1) * 56] = struct.pack(PHDR, t, f, o, v, v, fs, ms, al)
    out[lo["interp"]:lo["interp"] + len(OLD_INTERP)] = OLD_INTERP
    out[lo["text"]:lo["text"] + len(TEXT)] = TEXT
    for i, (name, shndx) in enumerate(((0, 0), (1, 2), (2, 2))):
        out[lo["dynsym"] + i * 24:lo["dynsym"] + (i + 1) * 24] = struct.pack(SYM, name, 0x12 if i else 0, 0, shndx, BASE + lo["text"], 16)
    out[lo["shstr"]:lo["shstr"] + len(SHSTR)] = SHSTR
    table = [section("", 0, 0, 0, 0, 0),
             section(".interp", 1, 2, BASE + lo["interp"], lo["interp"], len(OLD_INTERP)),
             section(".text", 1, 6, BASE + lo["text"], lo["text"], len(TEXT), align=8),
             section(".dynsym", 11, 2, BASE + lo["dynsym"], lo["dynsym"], 72, info=1, align=8, entsize=24),
             section(".shstrtab", 3, 0, 0, lo["shstr"], len(SHSTR))]
    out[lo["shdr"]:lo["shdr"] + 5 * 64] = b"".join(table)
    return bytes(out)


def build_patched(upstream):
    """Simulate a loader-path patch: new headers in front, old header area wiped, sections renumbered."""
    lo = layout()
    v0 = BASE - SHIFT
    header = bytearray(SHIFT)
    header[0:64] = struct.pack(EHDR, IDENT, 2, 183, 1, BASE + lo["text"], 64, lo["shdr"] + SHIFT, 0, 64, 56, 5, 64, 5, 4)
    interp_off = 64 + 5 * 56
    phdrs = [(6, 4, 64, v0 + 64, 280, 280, 8), (3, 4, interp_off, v0 + interp_off, len(NEW_INTERP), len(NEW_INTERP), 1),
             (1, 6, 0, v0, SHIFT, SHIFT, 0x1000), (1, 5, SHIFT, BASE, lo["shstr"], lo["shstr"], 0x1000),
             (0x6474E551, 6, SHIFT, 0, 0, 0x100000, 0)]
    for i, (t, f, o, v, fs, ms, al) in enumerate(phdrs):
        header[64 + i * 56:64 + (i + 1) * 56] = struct.pack(PHDR, t, f, o, v, v, fs, ms, al)
    header[interp_off:interp_off + len(NEW_INTERP)] = NEW_INTERP
    body = bytearray(upstream)
    body[0:lo["phdr_end"]] = bytes(lo["phdr_end"])
    body[lo["interp"]:lo["interp"] + len(OLD_INTERP)] = b"X" * (len(OLD_INTERP) - 1) + b"\0"
    for i in range(3):   # .text moves from section index 2 to 3
        at = lo["dynsym"] + i * 24 + 6
        if struct.unpack_from("<H", body, at)[0] == 2:
            struct.pack_into("<H", body, at, 3)
    table = [section("", 0, 0, 0, 0, 0),
             section(".interp", 1, 2, v0 + interp_off, interp_off, len(NEW_INTERP)),
             section(".dynsym", 11, 2, BASE + lo["dynsym"], lo["dynsym"] + SHIFT, 72, info=1, align=8, entsize=24),
             section(".text", 1, 6, BASE + lo["text"], lo["text"] + SHIFT, len(TEXT), align=8),
             section(".shstrtab", 3, 0, 0, lo["shstr"] + SHIFT, len(SHSTR))]
    body[lo["shdr"]:lo["shdr"] + 5 * 64] = b"".join(table)
    return bytes(header) + bytes(body)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.up = build_upstream()
        self.patched = build_patched(self.up)

    def check(self, mutate):
        data = bytearray(self.patched)
        mutate(data)
        return verify(self.up, bytes(data))[0]

    def test_a_faithful_loader_patch_is_accepted_and_the_new_loader_reported(self):
        problems, interpreter = verify(self.up, self.patched)
        self.assertEqual(problems, [])
        self.assertEqual(interpreter, NEW_INTERP[:-1].decode())

    def test_tampering_is_refused(self):
        lo = layout()
        phdr_at = lambda index: 64 + index * 56  # noqa: E731
        cases = {
            "a flipped bit in the code": lambda d: d.__setitem__(SHIFT + lo["text"] + 100, d[SHIFT + lo["text"] + 100] ^ 1),
            "a changed entry point": lambda d: d.__setitem__(24, d[24] ^ 1),
            "an executable new segment": lambda d: struct.pack_into("<I", d, phdr_at(2) + 4, 7),
            "a nonzero byte in the padding": lambda d: d.__setitem__(SHIFT - 100, 1),
            "an unrelated dynsym byte": lambda d: d.__setitem__(SHIFT + lo["dynsym"] + 24 + 8, 0xFF),
            "a dynsym index pointing at the wrong section": lambda d: struct.pack_into("<H", d, SHIFT + lo["dynsym"] + 24 + 6, 1),
            "extra bytes in the old loader area": lambda d: d.__setitem__(SHIFT + lo["interp"] + 3, 0x41),
            "a nonzero byte in the old header": lambda d: d.__setitem__(SHIFT + 5, 1),
            "a shrunk upstream segment": lambda d: struct.pack_into("<Q", d, phdr_at(3) + 32, 1),
            "a section address change": lambda d: struct.pack_into("<Q", d, len(d) - 2 * 64 + 16, 123),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.assertTrue(self.check(mutate), f"{label} was accepted")

    def test_a_file_that_is_not_larger_or_not_elf_is_refused(self):
        self.assertTrue(verify(self.patched, self.up)[0])
        with self.assertRaises(SystemExit):
            verify(b"not an elf file", self.patched)
