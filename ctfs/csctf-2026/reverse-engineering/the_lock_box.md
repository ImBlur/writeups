# Operation Dawn — Annex 06: Ash Army Gate Lock (model 43-K)

## Challenge

> The Ash gate guards run a small field unit at the north canal crossing: give it the pass phrase and it opens the gate or refuses. We took one. It will not tell you the phrase it is waiting for. Work out the phrase it accepts.
>
> Flag format: `CSCTF{...}`

We're given a binary (`lockbox`) and, across the course of the challenge, several decompiled functions.

---

## 1. Initial recon

Running the binary:

```
$ ./lockbox
ASH ARMY GATE LOCK  model 43-K  (field unit, north canal)
usage: gatelock <status|log|open> [phrase]
```

The three subcommands are `status`, `log`, and `open`. Only `open` takes a phrase and matters for the challenge.

## 2. The dispatcher

The entry point for commands is `FUN_001011c0`. The interesting branch:

```c
iVar3 = strcmp(__s1,"open");
if (iVar3 == 0) {
    if (param_1 == 2) {
        puts("open: supply a pass phrase");
    } else {
        lVar4 = FUN_00101490(*(undefined8 *)(param_2 + 0x10), local_128);
        if (lVar4 == 0x21) {           // length 33 → XOR decoy
            /* compare (input[i] ^ 0x5b) == DAT_00102200[i] */
            ...
        }
        if (DAT_00104014 == 0x5a) {    // 'Z'
            puts("GATE: pass phrase accepted - crossing open");
        } else {
            puts("GATE: pass phrase refused - crossing barred");
        }
    }
}
```

Two observations:

- The **actual** gate decision is `DAT_00104014 == 0x5a`. That global is what matters.
- The 33-byte XOR comparison against `DAT_00102200` is a **decoy**. It only prints *"the quartermaster laughs - that is last week's code, soldier"* and never affects `DAT_00104014`.

## 3. `FUN_00101490` — input handling

```c
size_t FUN_00101490(char *param_1, char *param_2)
{
    *param_2 = '\0';
    strncpy(param_2, param_1, 0xff);
    param_2[0xff] = '\0';
    sVar1 = strlen(param_2);
    while (true) {
        if (sVar1 == 0) return 0;
        sVar2 = sVar1 - 1;
        if (param_2[sVar2] != '\n' && param_2[sVar2] != '\r') break;
        param_2[sVar2] = '\0';
        sVar1 = sVar2;
    }
    return sVar1;
}
```

This is just a safe input copy with trailing `\n`/`\r` stripped. It returns the resulting length. No validation.

## 4. The real validator — `_INIT_1`

The function that writes `DAT_00104014` is `_INIT_1`:

```c
iVar2 = strcmp(*(char **)(param_2 + 8), "open");
if (iVar2 == 0) {
    lVar3 = FUN_00101490(*(undefined8 *)(param_2 + 0x10), local_128);
    if (lVar3 == 0x2c) {                    // 44 bytes
        bVar4 = 1;
        lVar3 = 0;
        bVar1 = true;
        iVar2 = 0x5b;
        do {
            uVar6 = (uint)lVar3;
            bVar5 = local_128[lVar3] ^ (byte)iVar2;
            bVar5 = (bVar5 << (bVar4 & 7) | bVar5 >> 8 - (bVar4 & 7))
                    + (&DAT_0010224d)[uVar6 & 7];
            if (bVar5 != (&DAT_00102255)[lVar3]) {
                bVar1 = false;
            }
            lVar3 = lVar3 + 1;
            bVar4 = bVar4 + 3;
            iVar2 = iVar2 + uVar6 + (uint)bVar5;
        } while (lVar3 != 0x2c);
        DAT_00104014 = (-(uint)!bVar1 & 0xffffffbd) + 0x5a;
    }
}
```

### Formalising the recurrence

Let `input[0..43]` be the 44-byte phrase. Initialize:

```
state = 0x5b
rot   = 1
```

For each `i` in `0..43`:

```
r      = rot & 7                          # rotate amount, increments by 3 each iter
y      = rol8(input[i] ^ state, r)        # 8-bit rotate-left
y      = (y + key1[i & 7]) & 0xff
require y == key2[i]
state  = (state + i + key2[i]) & 0xff
rot   += 3
```

Where:
- `key1` = 8 bytes at `DAT_0010224d`
- `key2` = 44 bytes at `DAT_00102255`

The final write:

```c
DAT_00104014 = (-(uint)!bVar1 & 0xffffffbd) + 0x5a;
```

- If `bVar1` is true (all bytes matched): `!(1) = 0`, so `DAT_00104014 = 0x5a` → **accepted**.
- If `bVar1` is false: `!(0) = 1`, so `DAT_00104014 = (0xffffffbd) + 0x5a = 0x17` (mod 2³²) → **refused**.

So we need **all 44 bytes** to satisfy the recurrence.

## 5. Locating the keys

The keys sit in the binary's `.data`/`.rodata` region. In Ghidra the base is `0x100000`, but under GDB with a PIE image at `$piebase = 0x555555554000`, the runtime addresses are:

```
key1: $piebase + 0x224d  (8 bytes)
key2: $piebase + 0x2255  (44 bytes)
```

> **Note:** the earlier mistake of using `$piebase + 0x10224d` fails because Ghidra's `0x100000` image base is already baked into the decompiler output — subtract it to get the true file offset.

Dumping at runtime:

```gdb
pwndbg> x/8xb  0x555555554000+0x224d
0x55555555624d: 0x63 0x0e 0xfa 0xb0 0xe3 0x84 0x22 0x68

pwndbg> x/44xb 0x555555554000+0x2255
0x555555556255: 0x93 0xe9 0xc7 0x87 0x90 0x48 0x03 0x30
0x55555555625d: 0x89 0xd9 0x60 0xb5 0xb9 0x4a 0x45 0x33
0x555555556265: 0x46 0x08 0xb7 0xa6 0x40 0x3f 0x85 0x53
0x55555555626d: 0xfb 0x4f 0x64 0xf1 0xcc 0xdb 0xc5 0x44
0x555555556275: 0x7b 0x17 0xa3 0x2e 0x45 0x0a 0x08 0xb0
0x55555555627d: 0x14 0xdf 0x9f 0xde
```

So:

```python
key1 = bytes([0x63,0x0e,0xfa,0xb0,0xe3,0x84,0x22,0x68])
key2 = bytes([0x93,0xe9,0xc7,0x87,0x90,0x48,0x03,0x30,
              0x89,0xd9,0x60,0xb5,0xb9,0x4a,0x45,0x33,
              0x46,0x08,0xb7,0xa6,0x40,0x3f,0x85,0x53,
              0xfb,0x4f,0x64,0xf1,0xcc,0xdb,0xc5,0x44,
              0x7b,0x17,0xa3,0x2e,0x45,0x0a,0x08,0xb0,
              0x14,0xdf,0x9f,0xde])
```

## 6. Inverting the recurrence

The forward transformation is:

```
y = rol8(input[i] ^ state, r) + key1[i & 7]   (mod 256)
```

Because `state` is updated using only `i` and `key2[i]` (not `input[i]`), we can invert the transformation **one byte at a time, left to right**:

```
target   = (key2[i] - key1[i & 7]) & 0xff
rotated  = ror8(target, r)
input[i] = rotated ^ state
state    = (state + i + key2[i]) & 0xff
```

No search, no constraints — it's a **direct algebraic inversion**.

### Solver

```python
key1 = [0x63,0x0e,0xfa,0xb0,0xe3,0x84,0x22,0x68]
key2 = [0x93,0xe9,0xc7,0x87,0x90,0x48,0x03,0x30,
        0x89,0xd9,0x60,0xb5,0xb9,0x4a,0x45,0x33,
        0x46,0x08,0xb7,0xa6,0x40,0x3f,0x85,0x53,
        0xfb,0x4f,0x64,0xf1,0xcc,0xdb,0xc5,0x44,
        0x7b,0x17,0xa3,0x2e,0x45,0x0a,0x08,0xb0,
        0x14,0xdf,0x9f,0xde]

def rol8(x, r):
    r &= 7
    return x if r == 0 else ((x << r) | (x >> (8 - r))) & 0xff

def ror8(x, r):
    r &= 7
    return x if r == 0 else ((x >> r) | (x << (8 - r))) & 0xff

# sanity: re-implement the forward check
def check(phrase):
    state = 0x5b
    for i in range(44):
        r = (1 + 3*i) & 7
        y = (rol8(phrase[i] ^ state, r) + key1[i & 7]) & 0xff
        if y != key2[i]:
            return False
        state = (state + i + key2[i]) & 0xff
    return True

# invert
state = 0x5b
out = bytearray()
for i in range(44):
    r = (1 + 3*i) & 7
    target = (key2[i] - key1[i & 7]) & 0xff
    out.append(ror8(target, r) ^ state)
    state = (state + i + key2[i]) & 0xff

print(out.decode())
assert len(out) == 44 and check(out)
```

Output:

```
CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
```

## 7. Verification

```bash
$ ./lockbox open 'CSCTF{06_ash_hawk_road_at_garrisoned_38318f}'
GATE: pass phrase accepted - crossing open
```

Gate opens.

## 8. Why the decoy doesn't matter

The `DAT_00102200` XOR check in `FUN_001011c0` runs only when the phrase length is `0x21` (33 bytes). Our real phrase is `0x2c` (44 bytes) so the branch is never taken. Even if it were, matching it only triggers a taunt:

> *the quartermaster laughs - that is last week's code, soldier*

The only condition that affects `DAT_00104014` is the full 44-byte recurrence in `_INIT_1`. The decoy is a red herring designed to reward people who pattern-match XOR loops without tracing the actual write to the auth byte.

---

## Flag

```
CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
```

## Lessons / notes

1. **Trace the write.** The decisive line was `DAT_00104014 = ...`, not any `puts("accepted")`. Always find where the "success" flag is set.
2. **Ghidra image base ≠ runtime base.** If your debugger dump says *"Cannot access memory"*, you likely added Ghidra's `0x100000` base on top of `$piebase`. Subtract `0x100000` from every Ghidra vaddr before adding `$piebase`.
3. **Reversible vs. non-reversible state.** Here the feedback state (`iVar2`) depends only on public constants (`key2`), so the check is trivially invertible with a byte-at-a-time ror. If `state` depended on `input[i]`, you'd need to brute force / use Z3.
4. **Watch the length check.** `lVar3 == 0x2c` is 44 — a red flag that this is a real fixed-length passphrase, not a loose string comparison. The 33-byte check (`0x21`) is the decoy.