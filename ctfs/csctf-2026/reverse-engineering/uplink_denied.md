# CSCTF 2026 — `uplink_denied` Writeup

## Challenge

> A hostile-state operation disabled the Meridian-class command-authentication unit (CAU) aboard the fictional DORVIX-7, a satellite flown by an allied space agency in the Operation Dawn coalition. The CAU now rejects every operator command.
>
> Recover the 24-byte recovery key the CAU accepts. Static analysis is enough, and the binary is untrusted.
>
> **Attachment:** `cau_verify`, a Linux x86-64 ELF, 682,600 bytes
> **SHA-256:** `19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`
>
> **Flag format:** `CSCTF{...}`

## TL;DR

The verifier applies a **fully invertible** 64-bit hash to three consecutive 8-byte slices of the recovery key and compares each result to a hard-coded constant. Because the hash is a composition of bijections (odd multiplications mod 2⁶⁴ and an involution `v ↦ v ^ (v >> 33)`), each slice can be recovered algebraically in O(1). No brute force and no symbolic execution are required.

```
CSCTF{cau_reset_09ff4472cbe8e0}
```

---

## 1. Reconnaissance

```bash
$ file cau_verify
cau_verify: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ ./cau_verify
Meridian-class CAU // recovery authentication
usage: cau_verify <recovery-key>
DENIED

$ ./cau_verify AAAAAAAAAAAAAAAAAAAAAAAA
DENIED
```

The binary takes a single 24-byte argument and prints either `ACCESS GRANTED` or `DENIED`. Since it's dynamically linked, the *safest* approach — and the one the challenge explicitly hints at ("the binary is untrusted") — is to avoid executing it under instrumentation and instead reason about the verifier statically.

## 2. Locating the verifier

Loading the ELF in Ghidra and searching for the banner string `"Meridian-class CAU // recovery authentication"` leads straight to `UndefinedFunction_004014f0`. Its decompilation (cleaned up):

```c
undefined8 UndefinedFunction_004014f0(int argc, char **argv)
{
    if (argc == 2) {
        char *key = argv[1];
        if (strlen(key) == 0x18) {                     // exactly 24 bytes
            uint64_t M1 = 0x9DF50AD53E8F1C7B;           // = -0x620af52ac170e385
            uint64_t M2 = 0xC17A4B92D6E30F55;           // = -0x3e85b46d291cf0ab

            uint64_t a = load64(key + 0);
            uint64_t b = load64(key + 8);
            uint64_t c = load64(key + 16);

            if (check(b) == 0x25d4e9834acb3349 &&
                check(a) == 0xd8dba78e270f595d &&
                check(c) == 0x976a0bc7e24f7338)
            {
                puts("ACCESS GRANTED");
                return 0;
            }
        }
    }
    puts("DENIED");
    return 1;
}
```

*(Ghidra's raw output is noisier — it inlines the three `check` calls and shuffles the constants — but the structure is the same: three 8-byte loads, three checks, three constants.)*

The helper `FUN_00401780` is just `load64` (a small wrapper around `memcpy`/`mov`). The heavy lifting is inline:

```c
uint64_t check(uint64_t x) {
    uint64_t u = ((x >> 33) ^ x) * M1;
    uint64_t v = ((u >> 33) ^ u) * M2;
    return v ^ (v >> 33);
}
```

## 3. The hash is a composition of bijections

Write `f(v) = v ^ (v >> 33)` over 64-bit unsigned integers. Two crucial properties:

1. **`f` is an involution:** `f(f(v)) = v`. This is because `v >> 33` only depends on the top 31 bits of `v` — shifting it again by 33 yields zero. So XOR-shifting twice is a no-op.
2. **`M1` and `M2` are odd.** Every odd integer is a unit in ℤ/2⁶⁴ℤ, so multiplication by `M1` or `M2` is a bijection.

Therefore `check` is a composition of three bijections:

```
check(x) = f( M2 · f( M1 · f(x) ) )
```

and it can be inverted in exactly the reverse order.

## 4. Algebraic inversion

```python
MASK = (1 << 64) - 1
M1 = (-0x620af52ac170e385) & MASK    # 0x9DF50AD53E8F1C7B
M2 = (-0x3e85b46d291cf0ab) & MASK    # 0xC17A4B92D6E30F55
iM1 = pow(M1, -1, 1 << 64)
iM2 = pow(M2, -1, 1 << 64)

f = lambda v: (v ^ (v >> 33)) & MASK

def check(x):
    u = f((x * M1) & MASK)
    u = f((u * M2) & MASK)
    return u

def invert(C):
    v = f(C)                 # undo outer f
    v = (v * iM2) & MASK     # undo * M2
    v = f(v)                 # undo middle f
    v = (v * iM1) & MASK     # undo * M1
    return f(v)              # undo inner f
```

Feeding the three constants through `invert` gives three 8-byte little-endian chunks:

| constant | `invert(constant)` (LE) | printable? |
|---|---|---|
| `0xd8dba78e270f595d` | `b'cau_rese'` | ✅ |
| `0x25d4e9834acb3349` | `b't_09ff44'` | ✅ |
| `0x976a0bc7e24f7338` | `b'72cbe8e0'` | ✅ |

All three chunks are printable ASCII — a strong signal we're on the right track. Concatenated in the order the constants appear in the checker (offset 0 → offset 8 → offset 16):

```
cau_rese + t_09ff44 + 72cbe8e0  =  "cau_reset_09ff4472cbe8e0"
```

That's 24 bytes, printable, contains no NULs, and spells a sensible phrase — exactly what the CAU expects.

## 5. Verify

```python
key = b'cau_reset_09ff4472cbe8e0'
assert len(key) == 24
for i, expect in zip((0, 8, 16),
                     (0xd8dba78e270f595d,
                      0x25d4e9834acb3349,
                      0x976a0bc7e24f7338)):
    x = int.from_bytes(key[i:i+8], "little")
    assert check(x) == expect
print("all checks pass")
```

All three checks pass, so the flag is:

```
CSCTF{cau_reset_09ff4472cbe8e0}
```

---

## Appendix A — Why we abandoned symbolic execution

The natural first instinct for a "recover the accepted input" challenge is to reach for `angr`. We tried, and it works, but the effort is disproportionate here:

1. **`entry_state(args=[..., symbolic])` rejects bit-vectors.** Modern angr's `add_string` accepts only string literals or claripy `String` ASTs; a plain `BVS` raises `ValueError: String must be either string literal or claripy AST`. Workarounds exist (build the argv array in memory manually via `call_state`, or symbolic-store over a placeholder), but they're fiddly.
2. **Symbolic memory stores can fail.** On Python 3.14 + bleeding-edge angr, `state.memory.store(addr, claripy.BVV(...))` raised `SimMemoryError: memory can only store claripy Expression` — a version-compatibility issue, not a script bug. Pinning the venv to Python 3.12 fixes it.
3. **The search space is small anyway.** Once you notice that all three checks are invertible, `sm.explore(find=...)` becomes a very expensive way to compute `pow(M1, -1, 2**64)`.

The algebraic solve runs in **under a millisecond**; the angr solve takes minutes to hours depending on how the constraints are written. When a verifier is a composition of bijections, invert it — don't explore it.

## Appendix B — Full solver

```python
#!/usr/bin/env python3
"""Invert the Meridian CAU recovery-key checker."""

MASK = (1 << 64) - 1
M1 = (-0x620af52ac170e385) & MASK
M2 = (-0x3e85b46d291cf0ab) & MASK
iM1 = pow(M1, -1, 1 << 64)
iM2 = pow(M2, -1, 1 << 64)

def f(v):  return (v ^ (v >> 33)) & MASK

def check(x):
    u = f((x * M1) & MASK)
    u = f((u * M2) & MASK)
    return u

def invert(C):
    v = f(C)
    v = (v * iM2) & MASK
    v = f(v)
    v = (v * iM1) & MASK
    return f(v)

CONSTS = [0xd8dba78e270f595d,   # offset 0
          0x25d4e9834acb3349,   # offset 8
          0x976a0bc7e24f7338]   # offset 16

chunks = [invert(C).to_bytes(8, "little") for C in CONSTS]
key    = b"".join(chunks)

print("key  :", key)
print("flag : CSCTF{" + key.decode("ascii") + "}")

# sanity check
for i, expect in zip((0, 8, 16), CONSTS):
    x = int.from_bytes(key[i:i+8], "little")
    assert check(x) == expect
print("verified OK")
```

Output:

```
key  : b'cau_reset_09ff4472cbe8e0'
flag : CSCTF{cau_reset_09ff4472cbe8e0}
verified OK
```

## Appendix C — Lessons

- **Recognise involutions.** `f(v) = v ^ (v >> k)` for `k ≥ 32` appears constantly in CTF verifiers precisely because it's cheap, invertible, and mixes bits. Spotting it usually collapses a "reverse engineering" problem into a five-line algebra exercise.
- **Odd multipliers are invertible mod 2⁶⁴.** `pow(M, -1, 2**64)` is always well-defined when `M` is odd; no need for extended-Euclid implementations.
- **Look for printable output as a sanity check.** If an inversion produces non-printable bytes when the challenge asks for a "key," that's a signal your model of the hash is wrong — not that the answer is binary garbage.
- **Symbolic execution is a hammer.** On pure-arithmetic verifiers, algebra is always faster, more reliable, and immune to toolchain drift. Reserve angr for verifiers with genuine branching (crypto state machines, CRC tables with complex control flow, checksum cascades).