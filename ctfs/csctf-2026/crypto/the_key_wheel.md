# The Key Wheel — CSCTF 2026 Writeup

## Challenge Overview

We're given `key-unit-journal.cbor` (7,037 bytes, SHA-256 `bb14ef0e...b2c159`), a CBOR file representing the seized key-schedule journal of an "ASH Army Key Unit v3" device. The task: recover the **standing order** that predates the journal's recorded output window.

The flavor text tells us everything we need:
- A hostile-state unit seized the journal
- The **standing order** is among the sealed dispatches
- Its key **predates the recorded output window** — so it's not directly in the register

---

## 1. Parsing the CBOR

    import cbor2
    obj = cbor2.load(open("key-unit-journal.cbor", "rb"))

Top-level structure:

| Key | Type | Value |
|---|---|---|
| `device` | str | `"ASH ARMY KEY UNIT v3  (seized; key-schedule journal)"` |
| `scheme` | str | seal/decrypt description |
| `window_opens_tx` | int | `156` |
| `register` | list[int] | **1248 words** |
| `traffic` | list[dict] | 5 sealed dispatches |

### The Scheme

    seal: TX t keys on register outputs [8*t, 8*t+8);
          key = concat uint32be(word);
          ks = concat SHA-256(key || uint32be(i)) for i=0,1,..;
          plain = ciphertext ^ ks

So for a message at TX `t`:
- Take register words `register[8*t : 8*t+8]`
- Pack each as `uint32be` → 32-byte key
- Keystream = `SHA256(key || uint32be(0)) || SHA256(key || uint32be(1)) || ...`
- XOR with ciphertext

### The Traffic

| tx | role | sealed length |
|---|---|---|
| **155** | **standing order** | **42** |
| 156 | field dispatch | 162 |
| 157 | field dispatch | 58 |
| 158 | field dispatch | 51 |
| 161 | field dispatch | 43 |

`window_opens_tx = 156` — the standing order at **tx=155** is one step **before** the window.

---

## 2. Finding the TX → Register Mapping

We first assumed `t = tx`, which gave garbage for everything. Brute-forcing all combinations of block index, endianness, nonce order, and nonce start revealed the truth — the field dispatches decrypt perfectly with `t = tx - 156`:

    tx=156 → t=0  → "COVER TRAFFIC ONLY. the standing order went out one cycle
                       before this journal's window opens; its key is not in
                       this register. turn the key wheel back to read it."
    tx=157 → t=1  → "hold positions and keep to radio discipline until relieved"
    tx=158 → t=2  → "ration resupply reaches the forward line after dark"
    tx=161 → t=5  → "acknowledge all command traffic on the hour"

The dispatches confirm the scheme and the mapping. But note the taunt: **"turn the key wheel back to read it."**

---

## 3. The Register Is MT19937

With 1248 words and the mapping `t = tx - 156`, the register spans blocks `t = 0..155`, i.e. exactly **two full MT19937 cycles** (624 words each).

Testing:

    u0 = [untemper(w) for w in reg[:624]]
    u1 = [untemper(w) for w in reg[624:]]
    twist_seq(u0) == u1   # True

This confirms:
- Register words are **tempered MT19937 outputs**
- `reg[0:624]` is one full cycle, `reg[624:1248]` the next
- TX 156 is the **first** output of the window (`t=0`)

Therefore TX 155 (the standing order) is the **last 8 outputs of the previous cycle** — the words `S_{-1}[616:624]` where `S_{-1}` is the state that *precedes* `reg[0:624]`.

---

## 4. Untwisting to Recover the Previous State

The MT19937 twist is:

    for i in range(624):
        y = (st[i] & 0x80000000) | (st[(i+1)%624] & 0x7fffffff)
        st[i] = st[(i+397)%624] ^ (y >> 1)
        if y & 1:
            st[i] ^= 0x9908b0df

The inverse must handle the `i=623` quirk: when `i=623`, `(i+1)%624 = 0` refers to the **new** value `n[0]` (already overwritten). The correct inverse:

    def untwist(n):
        n = list(n); old = [0]*624
        for i in range(623, -1, -1):
            if i == 623:
                g = n[623] ^ n[396]          # n[0] is new
            elif i >= 227:
                g = n[i] ^ n[i-227]          # old[i+397] already known
            else:
                g = n[i] ^ old[i+397]        # recover old[i+397] first
            y_lsb = (g >> 31) & 1
            gp = (g ^ 0x9908b0df) if y_lsb else g
            y = ((gp << 1) & 0xffffffff) | y_lsb
            old[i]   = (old[i]   & 0x7fffffff) | (y & 0x80000000)
            if i < 623:
                old[i+1] = (old[i+1] & 0x80000000) | (y & 0x7fffffff)
        return old

Self-test: `twist(untwist(state)) == state` ✓

Applying it:

    S0 = [untemper(w) for w in reg[:624]]
    prev = untwist(S0)
    assert twist(prev) == S0

---

## 5. Extracting the Standing Order Key

The standing order at tx=155 uses the **last 8 outputs** of `prev`, tempered back to output form:

    last8 = [temper(x) for x in prev[616:624]]
    key = b"".join(struct.pack(">I", w) for w in last8)

Decrypt:

    sealed = next(e for e in obj["traffic"] if e["role"] == "standing order")["sealed"]
    ks = b""
    i = 0
    while len(ks) < len(sealed):
        ks += hashlib.sha256(key + struct.pack(">I", i)).digest()
        i += 1
    plain = bytes(a ^ b for a, b in zip(sealed, ks))
    print(plain.decode())

The plaintext is the standing order, which contains the flag in the format `CSCTF{...}`.

---

## 6. Full Solve Script

    #!/usr/bin/env python3
    import cbor2, hashlib, struct

    def temper(y):
        y ^= y >> 11; y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000; y ^= y >> 18
        return y & 0xffffffff

    def _ur(v, s):
        r = 0
        for i in range(31, -1, -1):
            b = (v >> i) & 1
            if i + s < 32: b ^= (r >> (i + s)) & 1
            r |= b << i
        return r & 0xffffffff

    def _ul(v, s, m):
        r = 0
        for i in range(32):
            b = (v >> i) & 1
            if i - s >= 0: b ^= ((r >> (i - s)) & 1) & ((m >> i) & 1)
            r |= b << i
        return r & 0xffffffff

    def untemper(y):
        y = _ur(y, 18); y = _ul(y, 15, 0xefc60000)
        y = _ul(y, 7, 0x9d2c5680); y = _ur(y, 11)
        return y

    def twist(st):
        st = st[:]
        for i in range(624):
            y = (st[i] & 0x80000000) | (st[(i+1)%624] & 0x7fffffff)
            st[i] = st[(i+397)%624] ^ (y >> 1)
            if y & 1: st[i] ^= 0x9908b0df
        return st

    def untwist(n):
        n = list(n); old = [0]*624
        for i in range(623, -1, -1):
            if i == 623:    g = n[623] ^ n[396]
            elif i >= 227:  g = n[i] ^ n[i-227]
            else:           g = n[i] ^ old[i+397]
            y_lsb = (g >> 31) & 1
            gp = (g ^ 0x9908b0df) if y_lsb else g
            y = ((gp << 1) & 0xffffffff) | y_lsb
            old[i] = (old[i] & 0x7fffffff) | (y & 0x80000000)
            if i < 623:
                old[i+1] = (old[i+1] & 0x80000000) | (y & 0x7fffffff)
        return old

    obj = cbor2.load(open("key-unit-journal.cbor", "rb"))
    reg = obj["register"]
    sealed = next(e for e in obj["traffic"] if e["role"] == "standing order")["sealed"]

    S0 = [untemper(w) for w in reg[:624]]
    prev = untwist(S0)
    last8 = [temper(x) for x in prev[616:624]]

    key = b"".join(struct.pack(">I", w) for w in last8)
    ks = b""; i = 0
    while len(ks) < len(sealed):
        ks += hashlib.sha256(key + struct.pack(">I", i)).digest()
        i += 1
    plain = bytes(a ^ b for a, b in zip(sealed, ks))
    print(plain.decode())

---

## 7. Flag

Running the script yields the standing order plaintext, whose embedded flag is:

    CSCTF{...}

---

## Lessons

1. **Read the flavor text carefully.** "Turn the key wheel back" was a direct hint that the previous MT state had to be reconstructed, not just indexed.
2. **MT19937 is invertible.** Given two consecutive cycles of tempered outputs, the preceding cycle is fully recoverable via `untwist` — the `i=623` wraparound is the classic pitfall.
3. **Confirm the mapping empirically.** Brute-forcing the `(block, endian, nonce order, nonce start)` tuple against a *known* plaintext (the cover-traffic dispatch) pinned down `t = tx - 156` before touching the target ciphertext.