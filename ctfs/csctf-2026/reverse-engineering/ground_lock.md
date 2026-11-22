# CSCTF 2026 — `fcunlock` writeup

**Challenge:** Recover the 24‑byte service code accepted by `fcunlock`. Submit as `CSCTF{<24 code bytes>}`.

**Provided artifact:** `fcunlock`, Linux x86‑64 ELF, 682,600 bytes, SHA‑256 `9634a7c4…d2922399`.

---

## 1. Recon

```
$ file fcunlock
fcunlock: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
          statically linked, for GNU/Linux 3.2.0, stripped

$ checksec --file=./fcunlock
RELRO: Partial   Canary: No   NX: Yes   PIE: No
RPATH: No        RUNPATH: No  Symbols: No  FORTIFY: No
```

Key facts from `checksec`:

- **No PIE** → every address in the binary is a fixed virtual address, so the `.data`/`.rodata` constants we care about can be read with a straightforward file offset.
- **Stripped + no symbols** → the decompiler will show functions as `FUN_…`, but with no PIE the target addresses remain stable.
- **Statically linked** → the binary is large (682,600 bytes) but the interesting logic is still confined to a small function reached from `_start`.

---

## 2. Decompiling `main`

Following `_start → __libc_start_main`, Ghidra presents the top‑level function as `FUN_004016da`. Reproduced verbatim:

```c
undefined8 FUN_004016da(int param_1, undefined8 *param_2)
{
  long lVar1;
  bool bVar2;
  undefined8 uVar3;
  long lVar4;
  int local_24;
  ulong local_20;
  ulong local_18;

  if (param_1 == 2) {
    lVar1 = param_2[1];
    lVar4 = thunk_FUN_0041e900(lVar1);
    if (lVar4 == 0x18) {
      bVar2 = true;
      for (local_18 = 0; local_18 < 3; local_18 = local_18 + 1) {
        local_20 = 0;
        for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
          local_20 = local_20 |
                     (ulong)*(byte *)(lVar1 + local_18 * 8 + (long)local_24) <<
                     ((byte)(local_24 << 3) & 0x3f);
        }
        lVar4 = FUN_00401655(local_20);
        if (lVar4 != *(long *)(&DAT_00479020 + (local_18 + 4) * 8)) {
          bVar2 = false;
        }
      }
      if (bVar2) {
        FUN_00410460("GRIFFON-FC ground-maintenance interlock released.");
        FUN_0040a170("Maintenance token: CSCTF{%.*s}\n",0x18,lVar1);
        uVar3 = 0;
      }
      else {
        FUN_00410460("ACCESS DENIED");
        uVar3 = 1;
      }
    }
    else {
      FUN_00410460("ACCESS DENIED");
      uVar3 = 1;
    }
  }
  else {
    FUN_0040a0b0(PTR_DAT_004a56c8,"usage: %s <service-code>\n",*param_2);
    uVar3 = 2;
  }
  return uVar3;
}
```

What this tells us, without any inference beyond the code itself:

1. `argc` must equal 2, i.e. the program is invoked with exactly one user argument: `argv[1]`.
2. `thunk_FUN_0041e900(argv[1])` must return `0x18` → **the input must be 24 bytes long**.
3. The 24 bytes are split into **three consecutive groups of 8 bytes**.
4. Each group is assembled into a 64‑bit integer with the loop

   ```c
   local_20 |= byte[local_18*8 + i] << (i*8)
   ```

   i.e. **little‑endian** interpretation of each 8‑byte block.
5. Each block is passed to `FUN_00401655`, and the result is compared with one of three fixed qwords in `.data`:

   - block 0 vs. `*(long*)(0x479020 + (0+4)*8) = 0x479040`
   - block 1 vs. `*(long*)(0x479020 + (1+4)*8) = 0x479048`
   - block 2 vs. `*(long*)(0x479020 + (2+4)*8) = 0x479050`

6. If all three match, the program prints

   ```
   Maintenance token: CSCTF{%.*s}
   ```

   with `%.*s` = `0x18` bytes of `argv[1]`. So if we recover the correct `argv[1]`, the binary itself prints the flag.

The problem therefore reduces to: **invert `FUN_00401655` on the three stored qwords at `0x479040 / 0x479048 / 0x479050`.**

---

## 3. Analysing `FUN_00401655`

Ghidra decompiles it as:

```c
ulong FUN_00401655(ulong param_1)
{
  ulong uVar1;

  uVar1 = (param_1 ^ param_1 >> 0x21) * -0xae502812aa7333;
  uVar1 = (uVar1 ^ uVar1 >> 0x21) * -0x3b314601e57a13ad;
  return uVar1 ^ uVar1 >> 0x21;
}
```

Rewriting the signed Ghidra literals as unsigned 64‑bit values:

| Ghidra literal | Value mod 2⁶⁴ |
|---|---|
| `-0xae502812aa7333` | `0xff51afd7ed558ccd` |
| `-0x3b314601e57a13ad` | `0xc4ceb9fe1a85ec53` |

and noting `0x21 = 33`, the function is:

```c
uint64_t F(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}
```

Every step is invertible over `uint64_t`:

- **`y = x ^ (x >> 33)`** — the shift is 33, so a second application adds no new information (`2·33 = 66 ≥ 64`); the inverse is **`x = y ^ (y >> 33)`**.
- **`y = x · C (mod 2^64)`** — both `C` values above are odd, hence units in `ℤ/2^64`, and the inverse is **`x = y · C⁻¹ (mod 2^64)`**, computed directly with `pow(C, -1, 2**64)`.

Unrolling the three shift‑XOR and two multiplication stages gives:

```python
def Finv(y):
    M = (1 << 64) - 1
    y &= M
    y ^= y >> 33
    y  = (y * pow(0xc4ceb9fe1a85ec53, -1, 1 << 64)) & M
    y ^= y >> 33
    y  = (y * pow(0xff51afd7ed558ccd, -1, 1 << 64)) & M
    y ^= y >> 33
    return y
```

Because every operation in `F` is a bijection on 64‑bit words, `Finv` recovers the original block exactly, with no search and no solver.

---

## 4. Extracting the three target qwords

From `main`, the comparisons read from `0x479040 + i*8` for `i = 0,1,2`. Since the binary has no PIE, those are plain virtual addresses in the file's initialised data.

```python
from elftools.elf.elffile import ELFFile
import struct

VA = 0x479040
with open('fcunlock', 'rb') as f:
    elf = ELFFile(f)
    for sec in elf.iter_sections():
        if sec['sh_addr'] <= VA < sec['sh_addr'] + sec['sh_size']:
            f.seek(sec['sh_offset'] + (VA - sec['sh_addr']))
            targets = struct.unpack('<QQQ', f.read(24))
            break
```

This yields the three qwords that `main` compares each block against.

---

## 5. Recovering the code

Applying `Finv` to each target and re‑packing in little‑endian order (matching the construction in `main`):

```python
code = b''.join(Finv(t).to_bytes(8, 'little') for t in targets)
print('code :', code)
print('FLAG : CSCTF{%s}' % code.decode('latin1'))
```

This produced the correct 24‑byte service code. The recovered bytes are printable ASCII — consistent with the fact that `main` prints them via `%.*s` as the contents of `CSCTF{…}`.

**Flag:** `CSCTF{HALCYON_1B5FC6D72036689A}`.

---
