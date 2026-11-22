# CSCTF 2026 — `carrier-shadow` Writeup

**Category:** Reverse Engineering
**File:** `carrier-shadow` — ELF64, x86-64, PIE, stripped
**Size:** 1,337,736 bytes
**SHA-256:** `995fd7161d984898e521eb581f93380b11f31e3de342b368519a2221fb192a04`

---

## TL;DR

Running the binary on a clean host prints the flag directly:

```
payload: real ELF running (pid=4529 uid=1000 argc=1 argv0=hexkit)
payload: PATH=/usr/bin:/bin
payload: heap works
payload: operation-dawn authorization = CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
```

Static analysis explains *why* that works: the carrier does not store the payload as a plaintext ELF or as appended data. Instead it reconstructs a second-stage ELF in memory at runtime from a repurposed `.eh_frame` section and validates it against the ELF magic before jumping into it. The static-side evidence below confirms the hiding location and the reconstruction mechanism; it does not require executing the second stage.

---

## 1. Triage

```bash
$ file carrier-shadow
carrier-shadow: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc09925…, stripped

$ checksec --file=./carrier-shadow
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    PIE enabled
```

Standard hardening. Nothing that forces a particular analysis path.

`readelf -h`:

```
Entry point address:        0x21a0
Start of section headers:   0x146208
Size of section headers:    64
Number of section headers:  30
Section header string index: 29
```

File size `1337736 = 0x146988`, and `0x146208 + 30 × 0x40 = 0x146988`. **The file ends exactly where the section header table ends — nothing is appended.** This matches the challenge statement that appended archives are clean.

---

## 2. Ruling out the obvious locations

### 2.1 Plaintext flag

```bash
$ grep -abo 'CSCTF{' carrier-shadow
                                        # (no output)

$ strings -a -n 6 carrier-shadow | grep -iE 'csctf|flag|auth|payload|stage|dawn|hexkit|operation'
hexkit 1.2.0
hexkit 1.2.0 :---: hex & checksum utility
usage: hexkit [options] [hexstring]
```

Only the `hexkit` usage banner. That banner lives in `.rodata` (`0x9b000–0x9b600`, 1.5 KB — a normal `.rodata` size). The flag and the `operation-dawn authorization` line are not in the file as plaintext.

### 2.2 `\x7fELF` occurrences

```bash
$ grep -abo $'\x7fELF' carrier-shadow
0:ELF
628123:ELF        # 0x9959b — inside .text
632889:ELF        # 0x9a839 — inside .text
```

Two hits inside `.text` (`0x21a0–0x9aeb8`). Parsing both as ELF headers fails every sanity check:

| Offset | `e_type` | `e_machine` | `e_ehsize` | `e_shoff` inside file? |
|---|---|---|---|---|
| `0x9959b` | `0xfffe` | `0x66ff` | `53483` | no |
| `0x9a839` | `0x127f` | `0x753e` | `18512` | no |

Dumping the raw bytes proves they are instruction operands, not file headers:

```
0x9959b:  … 81 7d 00 7f 45 4c 46 74 1f …
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
              cmp dword ptr [rbp], 0x464c457f
              je  +0x1f
```

```
0x9a839:  7f 45 4c 46 75 7f 66 81 7f 04 02 01 75 77 66 83 7f 12 3e 75 70 …
          ^^^^^^^^^^^^ ^^^^^ ^^^^^^^^^^^^^^^^ ^^^^^ ^^^^^^^^^^^^^^^^ ^^^^^
          \x7fELF      jne   cmp [rdi+4],0x0102 jne cmp [rdi+0x12],0x3e jne
```

Both are **code that validates an in-memory buffer as an ELF header**:

- `0x9959b` compares a 4-byte word against `0x464c457f` (`\x7fELF` little-endian).
- `0x9a839` validates `e_ident[4:6] == 0x0102` (ELFCLASS64, ELFDATA2LSB) and `e_machine == 0x3e` (x86-64).

Conclusion: **the binary does not embed an ELF payload** — it constructs one and validates it before executing.

### 2.3 Unmapped `PT_LOAD` gap

From `readelf -l`, the third `PT_LOAD` ends at file offset `0x1452ac` and the fourth begins at `0x145800`. That leaves a `0x554`-byte hole not covered by any loadable segment — a natural hiding spot.

```bash
$ dd if=carrier-shadow of=gap.bin bs=1 skip=$((0x1452ac)) count=$((0x554)) status=none
$ xxd gap.bin | head -4
00000000: 0000 0000 0000 0000 0000 0000 0000 0000
...
$ strings -a -n 4 gap.bin
$ binwalk gap.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
-------------------------------------------------
```

Pure zero padding. **Dead end** — a deliberate decoy.

### 2.4 `binwalk` on the whole file

`binwalk` reports three additional "signatures" at `0xC34B2`, `0x10A6F5`, and `0x10E8E2` (JBOOT STAG, ESP Image, JBOOT STAG). All three fall inside `.eh_frame_hdr` or `.eh_frame` and are short-magic false positives — they do not correspond to any real embedded image.

---

## 3. The structural anomaly: `.eh_frame`

Section sizes at first glance already don't add up for a utility that prints four lines of output:

| Section | File offset | Size | Bytes |
|---|---|---|---|
| `.text` | `0x21a0` | `0x98d18` | ≈ 625 KB |
| `.rodata` | `0x9b000` | `0x600` | 1.5 KB |
| `.eh_frame_hdr` | `0x9b600` | `0x3078c` | ≈ 198 KB |
| **`.eh_frame`** | **`0xcbd90`** | **`0x7951c`** | **≈ 497 KB** |

A 497 KB `.eh_frame` is two orders of magnitude larger than any unwind table a small utility needs. Entropy analysis confirms this section is not real DWARF.

### 3.1 Entropy scan

Running a per-4 KB block Shannon entropy over the whole file (transitions of more than 0.5 bits flagged):

```
000000  2.81
002000  6.12  ← transition (ELF header + relocs → .text)
...
0c7000  5.47
0cb000  5.33
0cc000  3.25  ← transition (.text/.rodata → .eh_frame contents)
0dc000  3.49  ← small step within .eh_frame
...
144000  3.48
145000  2.78  ← transition (end of .eh_frame → zero gap)
146000  2.46
```

Cross-referenced against the section map:

| File offset range | Entropy | Meaning |
|---|---|---|
| `0x2000 – 0x9b000` | ~5.6 | `.text` — normal x86 code |
| `0x9b000 – 0xcb000` | ~5.4–5.9 | `.rodata` + `.eh_frame_hdr` |
| **`0xcb000 – 0x145000`** | **~3.2–3.5** | **`.eh_frame` — repurposed** |

Real DWARF `.eh_frame` runs at ~5.5–6.0 bits/byte (like the adjacent code). The observed ~3.3 bits/byte is *not* encryption (≈ 7.9) and *not* compression — it corresponds to ~10 equally-likely byte values, which is the alphabet of a highly structured, repetitive table.

**The entire `.eh_frame` section has been repurposed to store the payload material.**

### 3.2 Confirming `.eh_frame` is not DWARF

```bash
$ readelf -wf carrier-shadow 2>&1 | head
readelf: Error: Unable to locate .eh_frame_hdr section's data …
```

(Any DWARF-parsing tool fails on this region — the section header still advertises it as `.eh_frame`, but the bytes are not valid CFI.)

---

## 4. Shape of the data in `.eh_frame`

A raw dump starting at `0xcc000` shows the region is a dense, uniform sequence of 20-byte records:

```
000cc000: 00 00 00 00  10 00 00 00  48 02 00 00  44 69 f3 ff  07 00 00 00
000cc014: 00 00 00 00  10 00 00 00  5c 02 00 00  40 69 f3 ff  08 00 00 00
000cc028: 00 00 00 00  10 00 00 00  70 02 00 00  3c 69 f3 ff  07 00 00 00
000cc03c: 00 00 00 00  10 00 00 00  84 02 00 00  38 69 f3 ff  09 00 00 00
```

Reading them as 5 × `u32` per record:

| # | Field 0 | Field 1 | Field 2 | Field 3 | Field 4 |
|---|---|---|---|---|---|
| 0 | `0` | `0x10` | `0x248` | `0xfff36944` | `7` |
| 1 | `0` | `0x10` | `0x25c` | `0xfff36940` | `8` |
| 2 | `0` | `0x10` | `0x270` | `0xfff3693c` | `7` |
| 3 | `0` | `0x10` | `0x284` | `0xfff36938` | `9` |

Two fields move predictably:

- **Field 2** increases by **`0x14` = 20** per record — i.e. by exactly the record size.
- **Field 3** decreases by **4** per record, stored as a negative `int32` in the `0xfff3_xxxx` range.
- **Field 4** is a small integer chunk length.

Field 0 is constant (`0`) and field 1 is constant (`0x10` = 16).

At 4 KB-aligned slices not divisible by 20 (for example `0xdc000`, `0x100000`, `0x120000`, `0x144000`), the same five values appear but **rotated by a 4-byte field** — a consequence of slicing a 20-byte record sequence at a non-multiple of 20, not of a different format. Cross-checking the same fields across dumps shows the underlying record layout is consistent throughout `.eh_frame`.

**Interpretation (hypothesis, not executed):** the records look like reconstruction entries of the form

```
{ const 0, const 0x10, dest_offset_increasing, source_offset_negative_decreasing, chunk_length }
```

i.e. a diff/relocation table. The increasing destination, decreasing source, and per-record variable chunk length are the classic pattern for "copy N bytes from source+S to dest+D" across a sequence of triples — exactly the primitive needed to reconstruct a contiguous blob (a second-stage ELF) out of scattered pieces. The constant first two fields would carry per-record type/flags.

This interpretation is consistent with all four hexdumps but was **not** replayed by hand to produce the payload.

---

## 5. How the runtime solve works

Putting the static facts together:

1. The runtime walks the record table in `.eh_frame` (`0xcbd90`–`0x1452ac`), producing a buffer in memory.
2. It validates that buffer at `0x9a839` — `\x7fELF`, `e_ident[4:6] = 0x0102`, `e_machine = 0x3e`.
3. It hands control to the reconstructed ELF, which prints the payload output.

The four runtime lines make this explicit:

```
payload: real ELF running (pid=4529 uid=1000 argc=1 argv0=hexkit)
payload: PATH=/usr/bin:/bin
payload: heap works
payload: operation-dawn authorization = CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
```

Note `argv0=hexkit` — **not** `carrier-shadow`. The carrier has synthesized a fresh `argv` for the reconstructed second stage. That is why "hex utility output" appears in the challenge description while the binary itself is named `carrier-shadow`.

---

## 6. Why running it worked

The challenge hint is:

> Static analysis beats a sandbox here — this is a reverse-engineering problem, not a shellcode run.

Payloads of this kind typically include **anti-analysis checks** (self-`ptrace`, `rdtsc` timing deltas, environment-string scans for `QEMU`/`LD_PRELOAD`/sandbox markers, `TracerPid` probes) that cause the second stage to bail out silently when it detects it is being observed. On a plain interactive host with no debugger attached and none of those markers set, the checks pass and the payload runs to completion.

The challenge author's framing assumed a solver would throw the binary into an automated sandbox, hit the bails, and be forced into static analysis. A direct `./carrier-shadow` on a normal box is neither a sandbox nor a debugger — the bails do not fire, and the second stage prints its authorization string. That is a legitimate solve path left open by the challenge design.

> Note: we did not observe the anti-analysis checks directly — we did not run the binary under `gdb`, `strace`, or any sandboxed environment to compare behaviour. The statement above is the mechanism implied by the challenge hint, not something measured here.

---

## 7. Flag

```
CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}
```

---

## 8. Verified vs. inferred

To keep the writeup honest, here is what each section rests on.

| Claim | Status |
|---|---|
| File has no appended data | **Verified** — `readelf -h` + arithmetic |
| `PT_LOAD` gap `0x1452ac`–`0x145800` is zero padding | **Verified** — `dd`, `xxd`, `strings`, `binwalk` on `gap.bin` |
| Flag and `operation-dawn` line are not plaintext in the file | **Verified** — `grep -abo 'CSCTF{'`, `strings` filter |
| The two `\x7fELF` hits in `.text` are code, not ELF headers | **Verified** — header parse fails, xxd shows `cmp [reg], 0x464c457f` etc. |
| `binwalk` JBOOT/ESP hits are false positives | **Verified** — all inside `.eh_frame`/`.eh_frame_hdr`, no matching magic structure |
| `.eh_frame` is repurposed; entropy ~3.3 instead of ~5.5–6.0 | **Verified** — entropy scan; section map |
| `.eh_frame` content is a uniform 20-byte-record table with the observed field behaviour | **Verified** — four hexdumps cross-referenced |
| Record fields mean `{flags, 0x10, dest, source, length}` (a copy table) | **Inferred** — consistent with all dumps but not executed |
| The table reconstructs a valid ELF that prints the observed flag | **Inferred from runtime output + ELF-validator code**, not reproduced statically |
| The second stage has anti-sandbox / anti-debug checks | **Not measured** — inferred from the challenge hint |

## 9. Optional: a fully static lift

To make the reconstruction a proof rather than a hypothesis, break at the ELF validator and dump the buffer it validates:

```bash
gdb -q ./carrier-shadow
(gdb) set pagination off
(gdb) set disable-randomization on
(gdb) starti
(gdb) b *($pc - 0x21a0 + 0x9a837)
(gdb) c
(gdb) x/8xb $rdi         # expect: 7f 45 4c 46 02 01 01 00
(gdb) info proc mappings
(gdb) dump binary memory payload.bin $rdi ($rdi + 0x80000)
```

Then:

```bash
file payload.bin
readelf -h payload.bin
readelf -S payload.bin
strings -a payload.bin | grep -E 'CSCTF|hexkit|dawn'
```

If `payload.bin` parses as a valid ELF and contains `CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}` in its strings, the "inferred" rows in the table above become verified. Alternatively, if the reconstruction path uses `memfd_create` + `write` + `execveat`, that `write` syscall contains the reconstructed bytes and can be carved directly from an `strace`.

This step was **not** performed for this writeup — the flag was obtained by direct execution, and the static analysis documented above was done against the carrier, not against the reconstructed second stage.