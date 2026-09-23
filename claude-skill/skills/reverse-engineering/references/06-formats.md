# Data reverse engineering

> Recovering a file format or protocol, then attacking the parser.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 21. Data reverse engineering — formats and protocols

The same evidence-first loop applies to data, not just code. Often the fastest way
into a program is through the format it parses: recover the grammar, and the
parser's bounds checks become obvious by their absence.

### Identify before you parse

```bash
$RE_PYTHON scripts/fmt_probe.py "$F"      # magic, entropy regions, candidate header fields
file "$F"                                 # libmagic's best guess
binwalk "$F"                              # embedded blobs, offsets, nested archives
hexyl -n 128 "$F"                         # the header, by eye (or xxd)
```

`fmt_probe.py` does the first three steps of this section in one call: it matches
the signature table below (**including the ones not at offset 0**), splits the
file into high/low entropy regions so the header/payload boundary is visible, and
lists the header offsets whose values look like a length, an offset or a count.
Every field it names is a **hypothesis** — confirm it by mutation, below.

Magic bytes worth knowing by sight — note that **some are not at offset 0**:

| Bytes | Format | Offset |
|---|---|---|
| `7F 45 4C 46` (`\x7FELF`) | ELF | 0 |
| `4D 5A` (`MZ`) | PE / DOS | 0, with the PE header at the `e_lfanew` offset |
| `FE ED FA CE` / `CF` | Mach-O 32 / 64-bit | 0 |
| `CA FE BA BE` | Mach-O fat (also Java `.class`) | 0 |
| `50 4B 03 04` (`PK`) | ZIP — **and** docx/xlsx/pptx/jar/apk | 0 |
| `1F 8B 08` | gzip | 0 |
| `42 5A 68` (`BZh`) | bzip2 | 0 |
| `FD 37 7A 58 5A` | xz | 0 |
| `28 B5 2F FD` | zstd | 0 |
| `89 50 4E 47 0D 0A 1A 0A` | PNG | 0 |
| `SQLite format 3\0` | SQLite | 0 |
| `75 73 74 61 72` (`ustar`) | tar | **257** |
| `43 44 30 30 31` (`CD001`) | ISO 9660 | **32769** |
| `hsqs` / `sqsh` | SquashFS (LE / BE) | 0 |
| `UBI#` | UBIFS | 0 |
| `27 05 19 56` | uImage (U-Boot) | 0 |

A magic match is a hypothesis, not an identification — `PK` is equally a ZIP, a
JAR, an APK and a Word document, and the distinction is inside.

### Map the structure

Headers, length fields, offsets, counts, checksums, timestamps. Per-region
entropy separates plain headers from compressed or encrypted payloads: a
low-entropy first 64 bytes followed by a uniformly high-entropy remainder is a
header plus a compressed body, and the boundary tells you where the length field
points.

### Infer fields by mutation

This is the highest-yield technique and it needs no reversing at all. Flip one
byte, feed it back to the consumer, observe the reaction:

- rejected with a specific error → you found a validated field
- accepted but the output changed → a data field, and you know its meaning
- **crashed** → you found the bug, and the mutation *is* the proof of concept
- rejected regardless of value → a checksum covers it; find the checksum first

Walk the header a byte at a time and record which offsets matter. That maps
fields, lengths and checks empirically rather than by guesswork.

### Compare samples

Hex-diff several instances of the same format to separate constant scaffolding
from variable payload. Constant across all samples → magic, version, or padding.
Varies with content length → a length field. Varies unpredictably → a checksum,
a timestamp, or a nonce.

### Formalise the grammar as you learn it

Write the hypothesis down as a runnable parser:

```bash
kaitai-struct-compiler -t python fmt.ksy    # spec -> a real parser
tshark -r capture.pcap -V | head -40        # or a dissector, if it is on the wire
$RE_PYTHON -c 'import construct; ...'       # or build the frame yourself
```

A Kaitai spec, a Wireshark dissector, or plain Python `struct` all work. A failed parse
is then a fast falsification signal instead of a vague doubt, and the parser is
reusable on the next sample.

### Then attack the parser

Once you know the grammar, the vulnerability questions become concrete: is a
length field trusted without bounding it against the actual buffer? Is a count
multiplied by an element size without an overflow check? Does an offset get added
to a base without a range check? Is the checksum verified *before* or *after* the
data is used? That last one is a whole family of bugs by itself.

---
