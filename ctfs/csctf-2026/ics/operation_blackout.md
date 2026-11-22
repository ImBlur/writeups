# CSCTF — Substation 0x4A2E Blackout: ICS Forensics Writeup

## Challenge summary

A regional energy grid lost power at substation `0x4A2E`. Five artifacts describe the same incident from different layers:

| Artifact | Role |
|---|---|
| `scada_network.pcap` | Network truth — what was actually sent on the wire |
| `hmi_config.xml` | HMI configuration / register map |
| `plc_firmware.bin` | Firmware identity (raw header bytes) |
| `substation_log.json` | Chronological operational log |
| `alarm_override.dat` | Binary alarm-threshold override blob |

The goal is to reconstruct the *agreed* incident across layers and hash a five-field serialization into the flag.

---

## Step 1 — Firmware header

The spec is explicit: **first 4 raw bytes**, uppercase hex with `0x` prefix — *not* the version string.

```bash
xxd -l 4 -p plc_firmware.bin
# 504c4331
```

Formatting per spec (uppercase):

```text
firmware_header_hex = 0x504C4331
```

> Trap avoided: the firmware version string and any ASCII banner are decoys. Only the raw header bytes are hashed.

---

## Step 2 — Find the malicious FC16 write

Filter for Modbus Write Multiple Registers:

```bash
tshark -r scada_network.pcap -Y "modbus.func_code == 16"
```

Output:

```text
31 293.000000 192.168.50.5 → 192.168.50.10 Modbus/TCP 83
   Query: Trans: 2; Unit: 1, Func: 16: Write Multiple Registers
```

Only one FC16 exists, so there is no ambiguity. Inspect it fully:

```bash
tshark -r scada_network.pcap -Y "frame.number == 31" -V
```

Key fields:

| Field | Value |
|---|---|
| Transaction ID | `2` |
| Unit ID | `1` |
| Function Code | `16` (`0x10`, Write Multiple Registers) |
| Reference Number (start register) | `40001` |
| Word Count | `64` |
| Byte Count | `16` |
| Register values | `22010` repeated (40001–40008) |
| Pcap UTC arrival | `2025-11-15T06:05:03Z` |

So:

```text
register_decimal = 40001
```

> Trap avoided: the pcap UTC arrival time (`06:05:03Z`) is **not** the field to hash. The spec demands the timestamp from the *log entry for the malicious FC16 write*.

---

## Step 3 — Reconcile the log

`substation_log.json` contains the authoritative timeline:

| Timestamp (Z) | Level | Source | Message |
|---|---|---|---|
| 06:00:00 | INFO | SCADA_HMI | Normal startup — `manifest_seed: 137` |
| 06:15:00 | INFO | HMI_CLIENT | Loading Q3_Equipment_Calibration.xml |
| **06:15:03** | **WARNING** | **PLC_FIRMWARE** | **Unexpected Modbus FC 0x10 write to read-only registers 40001-40064** |
| 06:15:03 | CRITICAL | PLC_FIRMWARE | Buffer overflow (247 bytes vs 128-byte limit) |
| 06:15:04 | CRITICAL | PLC_FIRMWARE | Alarm thresholds modified |
| 06:15:05 | WARNING | NETWORK_MONITOR | Outbound to 198.51.100.42:443 |
| 06:15:10 | CRITICAL | PLC_FIRMWARE | Firmware integrity check failed |
| 06:30:00 | ERROR | POWER_MONITOR | **Power outage at substation 0x4A2E** |
| 07:00:00 | INFO | INCIDENT_RESPONSE | Emergency shutdown |

The malicious FC16 write is the `06:15:03` WARNING entry — it matches the pcap on **function code (0x10), register range (40001–40064)**. The station ID `0x4A2E` is confirmed in the `06:30:00` outage entry.

```text
station_hex        = 0x4A2E
log_timestamp_iso  = 2025-11-15T06:15:03Z
```

> Note the pcap-vs-log skew (06:05 vs 06:15). The pcap is shifted relative to the operational log; the serialization spec resolves the conflict by mandating the **log timestamp**. This is the primary decoy of the challenge.

---

## Step 4 — Calibration seed

The seed is present as a named field in the log's first record:

```json
"manifest_seed": 137
```

Cross-check against `alarm_override.dat`:

```bash
xxd alarm_override.dat
```

```text
00000000: 414c 524d 0300 2e4a 0000 9ca4 0000 0055  ALRM...J.......U
00000010: 0000 00fa 4869 6768 2054 656d 7065 7261  ....High Tempera
...
00000060: 0000 01f4 0000 1388 4f76 6572 6375 7272  ........Overcurr
```

Parsing the little-endian blob:

- `414c524d` = magic `"ALRM"`
- `0300` = 3 alarm entries
- **`2e4a` = `0x4A2E`** — station ID, confirming the log
- Entry 1: `0x55` = 85 °C → `0xFA` = 250 °C, `"High Temperature Alarm"`
- Entry 2: `0xC8` = 200 (2.0 bar) → `0x0A` = 10 (0.1 bar), `"Low Pressure Alarm"`
- Entry 3: `0x1F4` = 500 A → `0x1388` = 5000 A, `"Overcurrent Protection"`

These match the `06:15:04` CRITICAL log line exactly (85→250 °C, 2.0→0.1 bar, 500→5000 A). The override blob corroborates the log; the seed itself comes from the log field.

```text
seed_decimal = 137
```

> Decoys rejected: `scada_blackout_2026` is explicitly not an input; the pcap epoch time is not the timestamp; the firmware version string is not the header.

---

## Step 5 — Serialize and hash

The spec requires literal `:` separators, no binary packing:

```text
<firmware_header_hex>:<station_hex>:<log_timestamp_iso>:<register_decimal>:<seed_decimal>
```

Assembled:

```text
0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137
```

Compute:

```bash
printf '%s' '0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137' | sha256sum
```

```python
import hashlib

preimage = "0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137"
print("CSCTF{" + hashlib.sha256(preimage.encode()).hexdigest()[:8] + "}")
```

Take the first 8 hex characters of the digest:

```text
CSCTF{<first_8_lowercase_hex>}
```

---

## Evidence-agreement matrix

| Field | pcap | log | alarm blob | firmware | HMI |
|---|---|---|---|---|---|
| Station `0x4A2E` | — | ✅ 06:30:00 | ✅ `2e4a` | — | ✅ |
| FC16 `0x10` | ✅ frame 31 | ✅ 06:15:03 | — | — | — |
| Registers `40001–40064` | ✅ start 40001, WC 64 | ✅ | — | — | ✅ |
| Timestamp `06:15:03Z` | ⚠️ pcap says 06:05:03 (skew) | ✅ authoritative | — | — | — |
| Seed `137` | — | ✅ `manifest_seed` | — | — | — |
| Header `504C4331` | — | — | — | ✅ raw bytes | — |

Every hashed field is corroborated by at least two independent layers, except the timestamp — where the spec explicitly designates the log as authoritative.

---

## Common pitfalls

1. **Using the pcap UTC time** (`06:05:03Z`) instead of the log timestamp — the main trap.
2. **Lowercasing** the `0x` hex fields (spec says uppercase).
3. **Using the firmware version string** instead of the first 4 raw bytes.
4. **Hex seed** instead of decimal `137`.
5. **Reformatting the timestamp** (dropping `T`/`Z`).
6. Including `scada_blackout_2026` or extra fields in the preimage.

## Flag format

```text
CSCTF{8_lowercase_hex}
```