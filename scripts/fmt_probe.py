#!/usr/bin/env python3
#    ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
#    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
#    ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
#    ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
#    ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
#    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
#
#    R E X @ S K I L L   ·   Reverse Engineering eXecution
#
#    Author :  Norbert Tihanyi
#    X      :  x.com/@TihanyiNorbert

"""Probe an unknown file or blob -- the skill, section 21 (data reverse engineering).

    python3 scripts/fmt_probe.py <file> [--window 256] [--json]

Identifies the format from magic bytes (including the ones that are NOT at offset
0), maps high/low entropy regions to separate headers from compressed payloads,
and guesses which header offsets look like length fields, offsets or counts.

This is for the data side of the job: recover the grammar and the parser's
missing bounds checks become obvious by their absence.
"""
from __future__ import annotations
import argparse, collections, json, math, re, sys

# (offset, magic, name). Offset None means "search anywhere in the first 64 KB".
MAGIC = [
    (0,     b"\x7fELF",                 "ELF executable/object"),
    (0,     b"MZ",                      "PE / DOS executable"),
    (0,     b"\xfe\xed\xfa\xce",        "Mach-O 32-bit BE"),
    (0,     b"\xce\xfa\xed\xfe",        "Mach-O 32-bit LE"),
    (0,     b"\xfe\xed\xfa\xcf",        "Mach-O 64-bit BE"),
    (0,     b"\xcf\xfa\xed\xfe",        "Mach-O 64-bit LE"),
    (0,     b"\xca\xfe\xba\xbe",        "Mach-O fat OR Java .class"),
    (0,     b"PK\x03\x04",              "ZIP (also jar/apk/docx/xlsx/odt)"),
    (0,     b"PK\x05\x06",              "ZIP, empty archive"),
    (0,     b"\x1f\x8b\x08",            "gzip"),
    (0,     b"BZh",                     "bzip2"),
    (0,     b"\xfd7zXZ\x00",            "xz"),
    (0,     b"\x28\xb5\x2f\xfd",        "zstd"),
    (0,     b"\x04\x22\x4d\x18",        "lz4"),
    (0,     b"7z\xbc\xaf\x27\x1c",      "7-Zip"),
    (0,     b"Rar!\x1a\x07",            "RAR"),
    (0,     b"\x89PNG\r\n\x1a\n",       "PNG"),
    (0,     b"\xff\xd8\xff",            "JPEG"),
    (0,     b"GIF8",                    "GIF"),
    (0,     b"%PDF-",                   "PDF"),
    (0,     b"SQLite format 3\x00",     "SQLite 3 database"),
    (0,     b"\xd0\xcf\x11\xe0",        "MS Compound File (doc/xls/msi)"),
    (0,     b"OggS",                    "Ogg"),
    (0,     b"\x00asm",                 "WebAssembly"),
    (0,     b"dex\n",                   "Android DEX"),
    (0,     b"\xed\xab\xee\xdb",        "RPM"),
    (0,     b"!<arch>\n",               "ar archive / .deb / static lib"),
    (0,     b"hsqs",                    "SquashFS LE"),
    (0,     b"sqsh",                    "SquashFS BE"),
    (0,     b"UBI#",                    "UBI volume"),
    (0,     b"UBI!",                    "UBIFS"),
    (0,     b"\x27\x05\x19\x56",        "uImage (U-Boot)"),
    (0,     b"\x85\x19",                "JFFS2 node (LE)"),
    (0,     b"-rom1fs-",                "romfs"),
    (0,     b"CrAU",                    "Android A/B payload"),
    (0,     b"ANDROID!",                "Android boot image"),
    (257,   b"ustar",                   "tar"),                 # NOT at offset 0
    (32769, b"CD001",                   "ISO 9660"),            # NOT at offset 0
    (None,  b"\x1f\x8b\x08",            "embedded gzip"),
    (None,  b"PK\x03\x04",              "embedded ZIP"),
    (None,  b"hsqs",                    "embedded SquashFS"),
    (None,  b"\x7fELF",                 "embedded ELF"),
]


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def identify(d: bytes):
    hits = []
    for off, magic, name in MAGIC:
        if off is None:
            start = 0
            while True:
                i = d.find(magic, start, 65536)
                if i < 0 or i == 0:
                    break
                hits.append({"offset": i, "magic": magic.hex(), "format": name, "embedded": True})
                start = i + 1
                if len(hits) > 24:
                    break
        elif d[off:off + len(magic)] == magic:
            hits.append({"offset": off, "magic": magic.hex(), "format": name, "embedded": False})
    return hits


def regions(d: bytes, w: int):
    """Contiguous runs of similar entropy -- the header/payload boundary shows up here."""
    if len(d) < w:
        return [{"start": 0, "end": len(d), "entropy": round(entropy(d), 2), "kind": "whole"}]
    def kind(e):
        return "high (compressed/encrypted)" if e > 7.0 else \
               "mixed" if e > 5.0 else "low (headers/text/code)"
    out, cur = [], None
    for i in range(0, len(d) - w + 1, w):
        e = entropy(d[i:i + w])
        k = kind(e)
        if cur and cur["kind"] == k:
            cur["end"] = i + w; cur["_e"].append(e)
        else:
            if cur:
                cur["entropy"] = round(sum(cur["_e"]) / len(cur["_e"]), 2); cur.pop("_e"); out.append(cur)
            cur = {"start": i, "end": i + w, "kind": k, "_e": [e]}
    if cur:
        cur["entropy"] = round(sum(cur["_e"]) / len(cur["_e"]), 2); cur.pop("_e"); out.append(cur)
    return out


def header_guess(d: bytes, n: int = 64):
    """Which header offsets plausibly hold a length, an offset or a count."""
    out, size = [], len(d)
    for off in range(0, min(n, max(0, len(d) - 4)), 2):
        for width, fmt in ((2, "u16"), (4, "u32")):
            if off + width > len(d):
                continue
            for endian, tag in (("little", "LE"), ("big", "BE")):
                v = int.from_bytes(d[off:off + width], endian)
                if v == 0:
                    continue
                note = None
                if v == size:
                    note = "== file size"
                elif v == size - off - width:
                    note = "== bytes remaining after this field"
                elif 0 < v < size and v > size * 0.5:
                    note = "plausible offset into the file"
                elif 0 < v <= 4096 and width == 2:
                    note = "plausible length or count"
                if note:
                    out.append({"offset": off, "type": f"{fmt}{tag}", "value": v, "note": note})
    return out[:20]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--window", type=int, default=256)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    d = open(a.file, "rb").read()

    R = {
        "file": a.file, "size": len(d), "entropy": round(entropy(d), 3),
        "magic": identify(d), "regions": regions(d, a.window),
        "header_fields": header_guess(d),
        "printable_ratio": round(sum(32 <= c < 127 for c in d[:4096]) / max(1, min(len(d), 4096)), 3),
    }
    if a.json:
        print(json.dumps(R, indent=2)); return 0

    print(f"\n=== {a.file}  ({len(d):,} bytes, entropy {R['entropy']})")
    print("\n--- magic")
    if not R["magic"]:
        print("  no known signature. Unknown/custom format, or headerless data.")
        print(f"  printable ratio of first 4 KB: {R['printable_ratio']} "
              f"({'text-like' if R['printable_ratio'] > 0.8 else 'binary'})")
    for h in R["magic"]:
        tag = "embedded @" if h["embedded"] else "at"
        print(f"  {h['format']:<34} {tag} 0x{h['offset']:x}")
    print("\n--- entropy regions (header/payload boundary)")
    for r in R["regions"][:12]:
        print(f"  0x{r['start']:08x}-0x{r['end']:08x}  {r['entropy']:>5}  {r['kind']}")
    if R["header_fields"]:
        print("\n--- header offsets that look like lengths/offsets/counts")
        print("    (each is a HYPOTHESIS -- confirm by mutation, section 21)")
        for f in R["header_fields"][:12]:
            print(f"  +0x{f['offset']:02x}  {f['type']:<6} {f['value']:<12} {f['note']}")
    print("\nNext: flip one byte at a candidate offset, feed it back to the consumer,")
    print("and watch the reaction. Rejected = validated field. Crashed = the bug.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
