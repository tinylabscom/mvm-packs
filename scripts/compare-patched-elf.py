#!/usr/bin/env python3
"""Verify that a loader-patched ELF is its upstream file plus a loader-path patch.

A patcher such as patchelf can change the interpreter path by inserting padding at
the front of the file, writing a new ELF header, program header table and
interpreter string there, and shifting everything else by a fixed amount. This tool
checks that claim instead of assuming it, and exits 0 only if ALL of these hold:

1. The new ELF header equals the old one except the program header count, which may
   grow, and the section-table offset, which must move by exactly the shift.
2. Every upstream program header except PT_PHDR and PT_INTERP reappears unchanged
   (flags, addresses, sizes, alignment) with its file offset moved by exactly the shift.
   Extra headers are allowed only as PT_PHDR, PT_INTERP, or one non-executable PT_LOAD
   wholly inside the inserted bytes whose addresses overlap no upstream segment; the new
   PT_PHDR and PT_INTERP must lie inside it.
3. In the inserted bytes, everything outside the ELF header, the program header table
   and the interpreter string is zero.
4. The old ELF header and program header table are zero in the patched file; the old
   interpreter string is zero or the patcher's 'X' filler.
5. Sections are matched by name (the patcher reorders them): same type, flags, address,
   size and alignment, file offset moved by exactly the shift, and link and info indexes
   that name the same section in both files. Only .interp may differ, and it must match
   the new PT_INTERP.
6. Every other byte of the body is identical at the shift, except dynamic-symbol
   section-index fields that name the same-named section in both files.

Usage: compare-patched-elf.py UPSTREAM PATCHED
It reads both files and prints the new interpreter path.
"""

import struct
import sys

PT_LOAD, PT_INTERP, PT_PHDR = 1, 3, 6
PF_X = 1
EHDR = "<16sHHIQQQIHHHHHH"
PHDR = "<IIQQQQQQ"
SHDR = "<IIQQQQIIQQ"


def parse(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("only 64-bit little-endian ELF files are supported")
    e = struct.unpack_from(EHDR, data, 0)
    info = {"ident": e[0], "type": e[1], "machine": e[2], "version": e[3], "entry": e[4],
            "phoff": e[5], "shoff": e[6], "flags": e[7], "ehsize": e[8], "phentsize": e[9],
            "phnum": e[10], "shentsize": e[11], "shnum": e[12], "shstrndx": e[13]}
    if info["phentsize"] != 56 or info["shentsize"] != 64:
        raise SystemExit("unexpected program or section header entry size")
    info["phdrs"] = [dict(zip(("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"),
                              struct.unpack_from(PHDR, data, info["phoff"] + i * 56)))
                     for i in range(info["phnum"])]
    info["shdrs"] = [dict(zip(("name", "type", "flags", "addr", "offset", "size", "link", "info",
                               "addralign", "entsize"),
                              struct.unpack_from(SHDR, data, info["shoff"] + i * 64)))
                     for i in range(info["shnum"])]
    strtab = info["shdrs"][info["shstrndx"]]["offset"]
    for section in info["shdrs"]:
        end = data.index(b"\0", strtab + section["name"])
        section["label"] = data[strtab + section["name"]:end].decode("ascii", "replace")
    interp = next((p for p in info["phdrs"] if p["type"] == PT_INTERP), None)
    info["interp"] = None if interp is None else (interp["offset"], interp["offset"] + interp["filesz"])
    return info


def verify(up, patched):
    """Return (problems, interpreter) for the pair."""
    problems = []
    shift = len(patched) - len(up)
    if shift <= 0:
        return ["the patched file is not larger than the upstream file"], None
    u, p = parse(up), parse(patched)
    if u["interp"] is None or p["interp"] is None:
        return ["both files must have a PT_INTERP segment"], None

    # 1. ELF header
    for key in ("ident", "type", "machine", "version", "entry", "flags", "ehsize", "phentsize",
                "shentsize", "shnum", "shstrndx"):
        if u[key] != p[key]:
            problems.append(f"ELF header field {key} differs")
    if p["shoff"] != u["shoff"] + shift:
        problems.append("section header table did not move by exactly the shift")
    if p["phnum"] < u["phnum"]:
        problems.append("the patched file has fewer program headers")

    # 2. program headers
    def key(h):
        return (h["type"], h["flags"], h["vaddr"], h["paddr"], h["filesz"], h["memsz"], h["align"])

    remaining = list(p["phdrs"])
    for header in u["phdrs"]:
        if header["type"] in (PT_PHDR, PT_INTERP):
            continue
        match = next((q for q in remaining if key(q) == key(header) and q["offset"] == header["offset"] + shift), None)
        if match is None:
            problems.append(f"upstream program header type {header['type']:#x} is missing or changed")
        else:
            remaining.remove(match)
    upstream_loads = [(h["vaddr"], h["vaddr"] + h["memsz"]) for h in u["phdrs"] if h["type"] == PT_LOAD]
    new_loads = []
    for header in remaining:
        if header["type"] in (PT_PHDR, PT_INTERP):
            continue
        end = header["vaddr"] + header["memsz"]
        ok = (header["type"] == PT_LOAD and not header["flags"] & PF_X
              and header["offset"] + header["filesz"] <= shift
              and header["filesz"] == header["memsz"]
              and not any(header["vaddr"] < b and a < end for a, b in upstream_loads))
        if ok:
            new_loads.append(header)
        else:
            problems.append(f"extra program header type {header['type']:#x} flags {header['flags']:#x} is not allowed")
    # The new PT_PHDR and PT_INTERP must live inside one new non-executable segment.
    for header in p["phdrs"]:
        if header["type"] in (PT_PHDR, PT_INTERP):
            inside = next((q for q in new_loads if q["offset"] <= header["offset"]
                           and header["offset"] + header["filesz"] <= q["offset"] + q["filesz"]), None)
            if inside is None or header["vaddr"] != inside["vaddr"] + header["offset"] - inside["offset"]:
                problems.append(f"program header type {header['type']:#x} is not inside the new segment")

    # 3. inserted bytes: only the ELF header, the program header table and the interpreter string
    table_end = p["phoff"] + p["phnum"] * 56
    allowed = [(0, 64), (p["phoff"], table_end), p["interp"]]
    if p["interp"][1] > shift or table_end > shift:
        problems.append("headers or the interpreter string extend past the inserted bytes")
    for i in range(shift):
        if patched[i] and not any(a <= i < b for a, b in allowed):
            problems.append(f"nonzero byte at offset {i} in the inserted bytes outside the headers")
            break
    if patched[p["interp"][1] - 1] != 0:
        problems.append("the new interpreter string is not NUL-terminated")

    # 4. the old header area: ELF header and program header table zeroed, old interpreter string
    #    zero or overwritten with the patcher's 'X' filler
    old_table_end = u["phoff"] + u["phnum"] * 56
    if any(patched[shift:shift + old_table_end]):
        problems.append("the old ELF header and program header table were not zeroed")
    old_interp = patched[shift + u["interp"][0]:shift + u["interp"][1]]
    if any(byte not in (0, 0x58) for byte in old_interp):
        problems.append("the old interpreter string was not zeroed or overwritten with filler")
    old_end = max(old_table_end, u["interp"][1])

    # 5. section headers, matched by name because the patcher reorders them
    labels = [x["label"] for x in u["shdrs"]]
    new_labels = [x["label"] for x in p["shdrs"]]
    if len(set(labels)) != len(labels) or sorted(labels) != sorted(new_labels):
        problems.append("section names are ambiguous or differ between the files")
    else:
        by_name = {x["label"]: x for x in p["shdrs"]}
        for a in u["shdrs"]:
            b = by_name[a["label"]]
            name = a["label"]
            for field in ("type", "flags", "entsize"):
                if a[field] != b[field]:
                    problems.append(f"section {name!r} field {field} differs")
            if name == ".interp":
                if (b["offset"], b["size"], b["addr"]) != (p["interp"][0], p["interp"][1] - p["interp"][0],
                                                           next(h["vaddr"] for h in p["phdrs"] if h["type"] == PT_INTERP)):
                    problems.append("the .interp section does not match the new PT_INTERP segment")
            else:
                for field in ("addr", "size", "addralign"):
                    if a[field] != b[field]:
                        problems.append(f"section {name!r} field {field} differs")
                if a["type"] not in (0, 8) and b["offset"] != a["offset"] + shift:
                    problems.append(f"section {name!r} offset did not move by exactly the shift")
            for field, translate in (("link", True), ("info", a["flags"] & 0x40 != 0 and a["type"] in (4, 9))):
                if translate and a[field]:
                    same = a[field] < len(labels) and b[field] < len(new_labels) and labels[a[field]] == new_labels[b[field]]
                else:
                    same = a[field] == b[field]
                if not same:
                    problems.append(f"section {name!r} field {field} points at a different section")

    # 6. the body, excluding the header area and the section header table
    table = (u["shoff"], u["shoff"] + u["shnum"] * 64)
    if table[1] != len(up):
        problems.append("the section header table is not the end of the file")
    dynsym = next((x for x in u["shdrs"] if x["label"] == ".dynsym" and x["type"] == 11), None)
    start = old_end
    while start < table[0] and not problems:
        end = min(table[0], start + (1 << 20))
        a, b = up[start:end], patched[start + shift:end + shift]
        if a != b:
            for i in range(len(a)):
                if a[i] == b[i]:
                    continue
                offset = start + i
                if (dynsym and dynsym["offset"] <= offset < dynsym["offset"] + dynsym["size"]
                        and (offset - dynsym["offset"]) % 24 in (6, 7)):
                    entry = offset - (offset - dynsym["offset"]) % 24
                    old_i = struct.unpack_from("<H", up, entry + 6)[0]
                    new_i = struct.unpack_from("<H", patched, entry + 6 + shift)[0]
                    if old_i < len(labels) and new_i < len(new_labels) and labels[old_i] == new_labels[new_i]:
                        continue
                problems.append(f"byte at upstream offset {offset} differs outside the permitted structures")
                break
        start = end
    interpreter = patched[p["interp"][0]:p["interp"][1]].split(b"\0")[0].decode("ascii", "replace")
    return problems, interpreter


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


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    up, patched = open(argv[1], "rb").read(), open(argv[2], "rb").read()
    problems, interpreter = verify(up, patched)
    print(f"upstream {len(up)} bytes, patched {len(patched)} bytes, shift {len(patched) - len(up)}")
    if problems:
        for problem in problems[:20]:
            print("PROBLEM:", problem)
        return 1
    print(f"patched interpreter: {interpreter}")
    print("verified: only the loader-path patch (new headers, zeroed old header area, shifted "
          "offsets, renumbered dynamic-symbol section indexes); all other bytes identical")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
