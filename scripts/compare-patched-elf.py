#!/usr/bin/env python3
"""Compare an ELF file with a loader-patched copy and report every byte that differs.

A patcher such as patchelf can rewrite the interpreter path by moving the program
headers and inserting padding, which shifts everything after the insertion point
by a fixed amount. This tool aligns the two files at that shift and lists the
byte ranges that are NOT identical, so a reviewer can see that the whole
executable body is unchanged and only header structures differ.

Usage: compare-patched-elf.py UPSTREAM PATCHED
It reads both files, changes nothing, and exits 0 only if every differing range
lies inside the ELF header, program header table, section header table, or the
interpreter string area, or is a dynamic symbol's section-index field that
names the same section in both files (sections get renumbered).
"""

import struct
import sys


def read_elf(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("only 64-bit little-endian ELF files are supported")
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)[0], struct.unpack_from("<Q", data, 0x28)[0]
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 0x36)
    return {"phoff": phoff, "phnum": phnum, "phentsize": phentsize, "shoff": shoff,
            "shnum": shnum, "shentsize": shentsize}


def expected_ranges(data, info, shift_after=None):
    """Byte ranges of structures a loader patch is expected to rewrite."""
    ranges = [(0, 64),
              (info["phoff"], info["phoff"] + info["phnum"] * info["phentsize"]),
              (info["shoff"], info["shoff"] + info["shnum"] * info["shentsize"])]
    for marker in (b"/lib/ld-musl", b"/lib/ld-linux", b"/nix/store"):
        i = data.find(marker)
        if 0 <= i < 1 << 16:
            ranges.append((i, i + 256))
    return ranges


def differing_ranges(up, patched, shift):
    """Ranges of upstream offsets whose bytes differ from patched[offset + shift]."""
    out, start = [], None
    limit = min(len(up), len(patched) - shift)
    chunk = 1 << 20
    for base in range(0, limit, chunk):
        a = up[base:base + chunk]
        b = patched[base + shift:base + shift + len(a)]
        if a == b:
            if start is not None:
                out.append((start, base))
                start = None
            continue
        for i in range(len(a)):
            same = a[i] == b[i]
            if not same and start is None:
                start = base + i
            elif same and start is not None:
                out.append((start, base + i))
                start = None
    if start is not None:
        out.append((start, limit))
    return out


def sections(data, info):
    """[(name, type, offset, size, entsize)] from the section header table."""
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, info["shoff"] + i * info["shentsize"])
               for i in range(info["shnum"])]
    strndx = struct.unpack_from("<H", data, 0x3E)[0]
    base = entries[strndx][4]

    def name(offset):
        end = data.index(b"\0", base + offset)
        return data[base + offset:end].decode("ascii", "replace")

    return [(name(e[0]), e[1], e[4], e[5], e[9]) for e in entries]


def symbol_index_remap(up, patched, up_info, patched_info, shift, start, end):
    """True if [start, end) of upstream is the st_shndx of a dynamic symbol whose new
    section index is exactly the patched file's index for the same-named section."""
    up_secs, new_secs = sections(up, up_info), sections(patched, patched_info)
    for name, kind, offset, size, entsize in up_secs:
        if name == ".dynsym" and kind == 11 and offset <= start and end <= offset + size and entsize == 24:
            entry = offset + (start - offset) // 24 * 24
            if not entry + 6 <= start and end <= entry + 8:
                return False
            old_index = struct.unpack_from("<H", up, entry + 6)[0]
            new_index = struct.unpack_from("<H", patched, entry + 6 + shift)[0]
            if old_index >= len(up_secs) or new_index >= len(new_secs):
                return False
            return up_secs[old_index][0] == new_secs[new_index][0]
    return False


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    up, patched = open(argv[1], "rb").read(), open(argv[2], "rb").read()
    shift = len(patched) - len(up)
    print(f"upstream {len(up)} bytes, patched {len(patched)} bytes, shift {shift}")
    # The first structural bytes differ before the shift applies; compare the bodies at the shift.
    ui, pi = read_elf(up), read_elf(patched)
    print("upstream headers:", ui)
    print("patched headers: ", pi)
    ranges = differing_ranges(up, patched, shift)
    outside = []
    allowed = expected_ranges(up, ui)
    remapped = 0
    for start, end in ranges:
        if any(a <= start and end <= b for a, b in allowed):
            continue
        if symbol_index_remap(up, patched, ui, pi, shift, start, end):
            remapped += 1
        else:
            outside.append((start, end))
    total = sum(e - s for s, e in ranges)
    print(f"{len(ranges)} differing range(s) at shift {shift}, {total} bytes in total")
    for start, end in ranges[:20]:
        print(f"  upstream offset {start}..{end} ({end - start} bytes)")
    if outside:
        print(f"{len(outside)} range(s) lie outside the expected header structures")
        return 1
    print(f"every differing range is a header structure or one of {remapped} dynamic-symbol "
          "section-index fields that point at the same-named section in the patched file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
