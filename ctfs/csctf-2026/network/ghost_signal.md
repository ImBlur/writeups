# CSCTF — Roaming Fraud Forensics: Reconstructing an SS7 → Diameter → Billing Intrusion

## Challenge Summary

A telecom operator observed fraudulent roaming charges and disputed billing events. Three evidence sources were provided:

| Artifact | Content | Role |
|---|---|---|
| `ss7_capture.pcap` | SS7/MAP/CAP signalling | Identifies the targeted **IMSI** |
| `diameter_capture.pcap` | Diameter over SCTP (3GPP SLh) | Yields the **full Session-Id** |
| `billing_events.json` | OCS billing export | Yields the **first anomalous Unix timestamp** |

**Flag derivation:** `sha256("<imsi>:<full_session_id>:<unix_ts>")[:8]`, lowercase hex, wrapped as `CSCTF{...}`.

---

## Evidence Inventory

### `diameter_capture.pcap`

```
capinfos diameter_capture.pcap
```

- 28 packets, Ethernet/IP/**SCTP**, 151.5 s duration
- Capture window: `2024-08-15 12:40:00` → `12:42:31` UTC (epoch `1723740000`–`1723740151`)
- Protocol hierarchy confirms all 28 frames dissect as **Diameter** (no port forcing needed)

### `billing_events.json`

- 45 events, `metadata.billing_system = "Diameter OCS (3GPP Cx)"`
- Capture window `1723740000`–`1723740500`, note says *"filter by the IMSI and session corroborated by the signalling captures"*

---

## Step 1 — SS7: Identify the Subscriber

The SS7 capture is where the intrusion begins. MAP/CAP operations such as `SendRoutingInfoForSM`, `AnyTimeInterrogation`, or `UpdateLocation` against a specific subscriber are the classic precursor to roaming fraud — they let an attacker learn or forge a subscriber's location so the core network will accept subsequent Diameter requests for it.

Key filters used:

```
gsm_map || tcap || sccp
gsm_map.opcode == 22   # SendRoutingInfoForSM
gsm_map.opcode == 2    # UpdateLocation
```

The suspect subscriber that emerges is:

```
IMSI = 226012014000001
```

**Why this IMSI stands out:** every legitimate subscriber in the billing export follows the pattern `22601201400020XX` (`…2000`–`…2011`, sequential). The anomalous IMSI `226012014000001` sits in a completely different block and never appears in the normal traffic — it is the only subscriber whose activity begins mid-capture.

---

## Step 2 — Diameter: Baseline vs. Anomaly

### Enumerate the capture first

The initial attempt filtered on `diameter.cmd.code == 272` (Credit-Control-Request) and returned nothing — a red herring. This capture is **not** Gy charging; it is **3GPP SLh Provide-Location**. The command codes present are:

| Code | Name |
|---|---|
| 301 | Provide-Location-Request (PLR) |
| 302 | Provide-Location-Answer (PLA) |

### Working extraction command

```
tshark -r diameter_capture.pcap -T fields \
  -e frame.number \
  -e frame.time_epoch \
  -e diameter.cmd.code \
  -e diameter.Session-Id \
  -e diameter.avp.code \
  | sort -n -k1,1
```

### Baseline behaviour (frames 1–24)

A perfectly regular 5-second cadence, sequence numbers incrementing `0 → 11`:

```
hss.eastern-tele.ro;1723740000;0
hss.eastern-tele.ro;1723740005;1
hss.eastern-tele.ro;1723740010;2
...
hss.eastern-tele.ro;1723740055;11
```

Each session consists of a PLR (301) and PLA (302), carrying AVP set `263,264,296,283,443,450,444,601/602`.

### The anomaly (frames 25–28)

After a **~95-second silent window** (`1723740055` → `1723740150`), the pattern breaks:

```
25  1723740150.000  301  hss.eastern-tele.ro;1723740150;49211
26  1723740150.200  301  hss.eastern-tele.ro;1723740150;49211
27  1723740150.500  302  hss.eastern-tele.ro;1723740150;49211
28  1723740151.500  302  hss.eastern-tele.ro;1723740150;49211
```

Two independent red flags:

1. **Sequence jump:** `11` → `49211` — far outside the monotonically incrementing baseline.
2. **Duplicate PLR/PLA:** the normal one-request/one-answer pattern is replaced by two requests followed by two answers.

### Extract the IMSI from the anomalous session

AVP `443` (grouped Subscription-Id) → `450` (type = `1`, IMSI) → `444` (Subscription-Id-Data):

```
tshark -r diameter_capture.pcap -Y 'frame.number>=25' -T fields \
  -e frame.number -e diameter.Session-Id -e diameter.Subscription-Id-Data
```

```
25  hss.eastern-tele.ro;1723740150;49211  226012014000001
26  hss.eastern-tele.ro;1723740150;49211  226012014000001
27  hss.eastern-tele.ro;1723740150;49211  226012014000001
28  hss.eastern-tele.ro;1723740150;49211  226012014000001
```

This **corroborates the SS7 finding** — same IMSI, same session, across two independent protocols.

```
FULL_SESSION_ID = hss.eastern-tele.ro;1723740150;49211
```

> ⚠️ The `49211` fragment alone is **not** the Session-Id. The derivation spec requires the entire string including the host, the epoch component, dots, and semicolons.

---

## Step 3 — Billing: First Anomalous Event

### Filter by the corroborated IMSI and session

```
jq -r '.events[] | select(.imsi=="226012014000001") | [.timestamp, .event_id, .session_id, .event_type, .anomaly] | @tsv' \
  billing_events.json | sort -n
```

| timestamp | event_id | event_type | anomaly |
|---|---|---|---|
| **1723740150** | **atk_0000** | **CCR-I** | **zero_charge_on_roaming** |
| 1723740154 | atk_0001 | CCR-I | zero_charge_on_roaming |
| 1723740158 | atk_0002 | CCR-I | zero_charge_on_roaming |
| 1723740162 | atk_0003 | CCR-I | zero_charge_on_roaming |
| 1723740166 | atk_0004 | CCR-I | zero_charge_on_roaming |
| 1723740170–1723740178 | pivot_0000–0004 | CCA | unusual_routing_path |

The **first anomalous billing event** is `atk_0000`:

```json
{
  "event_id": "atk_0000",
  "timestamp": 1723740150,
  "session_id": "hss.eastern-tele.ro;1723740150;49211",
  "imsi": "226012014000001",
  "target_number": "+40721000101",
  "event_type": "CCR-I",
  "charging_amount": 0.0,
  "status": "accepted",
  "anomaly": "zero_charge_on_roaming",
  "redirect_host": "intercept-49211.evil-domain.net"
}
```

```
UNIX_TIMESTAMP = 1723740150
```

Note the timestamp is already an integer (Unix seconds) — no ISO conversion needed.

---

## Step 4 — Flag Derivation

Serialize exactly per the spec, no hosts, no GTs, no event IDs:

```
226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150
```

```bash
printf '%s' '226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150' \
  | sha256sum | cut -c1-8
```

```python
import hashlib
s = "226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150"
print("CSCTF{" + hashlib.sha256(s.encode()).hexdigest()[:8] + "}")
```

```
CSCTF{<first 8 lowercase hex chars of the SHA-256>}
```

---

## Reconstructed Intrusion Chain

| Epoch | Layer | Observation |
|---|---|---|
| 1723740000–1723740055 | Diameter | Normal SLh cadence: 12 sessions, seq 0→11 |
| ~1723740055–1723740150 | **SS7** | Silent window — MAP operations target IMSI `226012014000001` |
| 1723740150.000 | Diameter | Forged session `…;49211` established (PLR) — seq jump `11 → 49211` |
| 1723740150.200 | Diameter | Duplicate PLR — replay/retry outside baseline profile |
| **1723740150** | **Billing** | **`atk_0000`: first zero-charge roaming CCR-I** |
| 1723740150.500–151.5 | Diameter | PLA(s) returned for `…;49211` |
| 1723740154–166 | Billing | `atk_0001–0004`: continued zero-charge CCR-I to `+40721000102–105` |
| 1723740170–178 | Billing | `pivot_0000–0004`: CCA with `unusual_routing_path`, `cscf.pivot.eastern-tele.ro` |
| — | Billing | Charges redirected to `intercept-49211.evil-domain.net` / `redirect-49211.evil-domain.net` |

**Narrative:** The attacker used SS7 signalling to position IMSI `226012014000001` for roaming under false pretenses. With the HSS (`hss.eastern-tele.ro`) now answering for that subscriber, a forged Diameter SLh session (`…;49211`) was established outside the normal cadence. That session was then used to originate zero-charge CCR-Initial events targeting a sequential block of numbers (`+40721000101`–`+40721000105`), while CCA responses redirected routing through `intercept-49211.evil-domain.net` and `redirect-49211.evil-domain.net` — the mechanism by which calls/SMS to those numbers would be intercepted rather than billed. The `49211` sequence number is the pivot that ties the Diameter session to the malicious redirect hosts.

---

## Pitfalls Encountered

| Symptom | Cause | Fix |
|---|---|---|
| `diameter.cmd.code==272` returns nothing | Capture is SLh (301/302), not Gy (272/280) | Enumerate `diameter.cmd.code` first |
| `diameter.cmd.name` "not valid" | Field alias absent in this tshark build | Use `diameter.cmd.code`; verify with `tshark -G fields` |
| Blank `-T fields` output | Invalid `-e` name errors go to **stderr**, stdout stays empty | Check stderr; fall back to raw `diameter.avp.code`/`avp.value` |
| `sort -t$'\t' -k3,3n` misorders | Numeric sort on a non-leading field | Use `sort -n -k1,1` on `frame.number` |
| Temptation to use `49211` as Session-Id | It is only the trailing fragment | Use the **entire** AVP 263 string |
| Confusing event ID with IMSI | Both end in `0001` patterns | IMSI is `226012014000001`; event is `atk_0000` |

---

## Appendix — Full Command Set

```bash
# 1. Sanity check: is Diameter being dissected?
tshark -r diameter_capture.pcap -q -z io,phs

# 2. Which command codes exist?
tshark -r diameter_capture.pcap -T fields -e diameter.cmd.code | sort -u

# 3. Per-frame overview
tshark -r diameter_capture.pcap -T fields \
  -e frame.number -e frame.time_epoch -e diameter.cmd.code \
  -e diameter.Session-Id -e diameter.avp.code | sort -n -k1,1

# 4. Anomalous session + IMSI
tshark -r diameter_capture.pcap -Y 'frame.number>=25' -T fields \
  -e frame.number -e diameter.Session-Id -e diameter.Subscription-Id-Data

# 5. First anomalous billing event
jq -r '.events[] | select(.imsi=="226012014000001") | [.timestamp,.event_id,.anomaly] | @tsv' \
  billing_events.json | sort -n | head -1

# 6. Flag
printf '%s' '226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150' \
  | sha256sum | cut -c1-8
```

---

## Takeaways

1. **Corroborate across layers.** The IMSI was independently recoverable from SS7 and from Diameter AVP 444; matching it against billing closed the loop. No single artifact was sufficient.
2. **Baseline before anomaly.** The 5-second cadence and `0→11` sequence numbers made `49211` and the 95-second gap unmistakable — pattern-of-life analysis beat signature matching.
3. **Read the spec literally.** The flag derivation explicitly warned against using just the GT fragment; `49211` would have produced a plausible-looking but wrong hash.
4. **Protocol identity matters.** Assuming Diameter meant Gy charging (command 272) sent the investigation down a dead end; `io,phs` plus a command-code enumeration immediately revealed SLh (301/302).