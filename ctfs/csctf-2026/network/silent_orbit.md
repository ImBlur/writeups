# Silent Orbit — Writeup

## Challenge summary

A modified CCSDS telemetry parser on the relay ground station was silently dropping the CFDP packets that belonged to the target transaction, so the relay never accumulated file coverage for that transaction and never emitted the deferred NAK that would have requested retransmission. The stream is raw concatenated CCSDS Space Packets, not a PCAP.

We recover the exact CFDP NAK PDU the normal relay would have sent.

---

## 1. Files

| File | Purpose |
|---|---|
| `telem_parser.exe` | Modified Windows parser (contains the anomaly) |
| `ground_station_rx.bin` | Raw concatenated CCSDS Space Packets captured from the downlink |
| `mission-profile.txt` | Relay rules / CFDP grammar used by the continuity cell |
| `README.txt` | Submission format |
| `SHA256SUMS` | Integrity |

The flag is the complete NAK PDU rendered as uppercase hex and wrapped as `CSCTF{...}`.

---

## 2. Unwrap the CCSDS Space Packets

`mission-profile.txt` says each record is:

```
[6-byte CCSDS 133.0-B-2 primary header][packet-data-length + 1 user-data octets]
```

with no resynchronisation on truncation. Parsing that structure yields 188 packets.

Only packets matching:

- PVN = `000`
- APID = `0x321`
- secondary-header flag = `0`
- sequence flags = `11`

are eligible. The stream happens to include a decoy (Packet 1, `APID 0x012`) and a second transaction (`APID 0x321`, tuple `03/09/02`) that must not contribute.

---

## 3. Parse CFDP PDUs (CCSDS 727.0-B-5, 1-octet entity IDs)

Each eligible user-data field is exactly one CFDP PDU. With one-octet source, sequence, and destination entity IDs the header is **7 bytes**:

```
[ byte 0 ]  version=001 | pdu_type | direction | tx_mode | crc_flag | large_file
[ byte 1:2 ] PDU data-field length (big-endian)
[ byte 3  ] segment control | length-of-entity-IDs | segment-metadata | reserved
[ byte 4  ] source entity ID
[ byte 5  ] transaction sequence number
[ byte 6  ] destination entity ID
```

Target filter from the profile:

```
version = 1, direction = toward receiver, tx_mode = acknowledged,
crc = 0, large_file = 0, (source, seq, dest) = (0x01, 0x07, 0x02)
```

This stream encodes **acknowledged** as `tx_mode = 0`, which is the inverse of the standard CCSDS 727 convention. The target packets all start with `0x20` (directives) or `0x30` (file data), confirming it.

Directive codes are challenge-specific:

```
0x04 → EOF        (Packet 188)
0x07 → Metadata   (Packet 3)
0x08 → NAK        (what the relay would have sent)
```

File Data uses the small-file offset (4 octets) followed by payload:

```
[ 4-byte offset ][ payload bytes ]
```

Metadata (Packet 3):

```
20 0008 00 01 07 02   07 0f 000000C0 00 00
```

- directive `0x07` (Metadata)
- checksum type = `0x0F` = NULL_CHECKSUM, closure = 0
- file size = `0x000000C0` = **192 bytes**
- source filename length = 0, dest filename length = 0, no option TLVs

EOF (Packet 188):

```
20 000a 00 01 07 02   04 00 00000000 000000C0
```

- directive `0x04`
- condition = 0 (No Error), spare = 0
- checksum = `00000000`
- file size = `0x000000C0` = 192, matches Metadata → accepted.

---

## 4. Identify the parser anomaly

`telem_parser.exe` re-implements the CCSDS 727 `tx_mode` bit polarity, i.e. it treats **`tx_mode = 1`** as *acknowledged*, exactly as the standard describes. But this relay encodes **`tx_mode = 0`** as acknowledged.

Consequence:

- every target Metadata packet (`0x20 …`) is rejected by the parser's eligibility gate as "unacknowledged mode",
- the parser never enters `COLLECT`,
- every target File Data packet (`0x30 …`) is also rejected,
- the parser never accumulates coverage,
- the relay never emits the deferred NAK.

That is exactly the "suppressed telemetry" described in the brief. A correct relay-side parser (one that follows this relay's own convention, `tx_mode = 0` = acknowledged) processes the same stream without touching any byte.

Note also that the File Data packet sequence counts in the CCSDS primary header are decoys: the mission profile explicitly says they are diagnostic metadata, not file-byte coverage. Coverage must come from the 4-byte offset field inside the CFDP File Data PDU.

---

## 5. Rebuild the relay state machine

### WAIT_METADATA

First valid target Metadata (Packet 3) is accepted:

- checksum type 15, closure 0, no option TLVs,
- file size = **`0xC0` = 192**.

Then state transitions to `COLLECT`. Any target File Data or EOF that occurred during `WAIT_METADATA` is permanently discarded (this drops Packet 4's sibling before the Metadata handshake — the stream's layout makes this consistent).

### COLLECT

Every target File Data with `seg_ctrl = 0` and `seg_meta = 0` whose non-wrapping `[offset, offset + payload_length)` end is ≤ 192 contributes a coverage interval. Duplicates and overlaps merge.

The stream deliberately splits coverage into two interleaved groups:

- Group 1 (`PKT4`–`PKT93`) covers the "even/off" offsets.
- Group 2 (`PKT94`–`PKT184`) covers the "odd/on" offsets, with `PKT184` duplicating `PKT183`.

Merged coverage across the full stream leaves exactly 12 single-byte holes inside `[0, 192)`:

```
[5,6) [19,20) [35,36) [51,52) [68,69) [83,84)
[101,102) [119,120) [138,139) [154,155) [171,172) [187,188)
```

### Accept the first EOF

Packet 188 is the first target EOF with:

- directive `0x04`,
- condition/spare `0x00`,
- null checksum `00000000`,
- no fault-location TLV (data-field length is exactly 10),
- file size `0xC0` = 192.

The relay snapshots coverage and stops.

---

## 6. Build the deferred NAK

NAK PDU header, again with this stream's `tx_mode = 0` = acknowledged convention:

```
[ byte 0 ]  v=001 | type=0 (File Directive) | dir=1 (toward sender) | tx=0 (ack) | crc=0 | lf=0
            = 0x28
[ byte 1:2 ] PDU data-field length
[ byte 3  ] seg_ctrl=0 | entity-ID len=0 (1 byte each) | seg_meta=0 | reserved=0 = 0x00
[ byte 4  ] src = 0x01
[ byte 5  ] seq = 0x07
[ byte 6  ] dst = 0x02
```

Data field:

```
[ 1 byte  ] directive = 0x08 (NAK)
[ 4 bytes ] scope start = 0x00000000
[ 4 bytes ] scope end   = 0x000000C0
[ N × 8  ] ascending, maximal, non-overlapping [start,end) request pairs
```

Lengths: `1 + 4 + 4 + 12×8 = 105 = 0x0069`.

Assembled PDU (hex, uppercase):

```text
280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC
```

---

## 7. Flag

```text
CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}
```

### Key takeaways

1. The primary-header sequence counts are decoys — file coverage comes only from the 4-byte offset in the CFDP File Data PDU.
2. The stream's `tx_mode` polarity is inverted relative to standard CCSDS 727, which is precisely what the modified parser got wrong: it applied the standard polarity and dropped every target packet, suppressing the recovery record entirely.
3. When in doubt, trust the bytes over the standard: reconstructing the relay from `mission-profile.txt` alone (without ever running the modified binary) is enough, because the eligibility rules and the state machine are fully specified.