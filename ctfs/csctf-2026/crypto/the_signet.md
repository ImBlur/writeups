# The Signet — CTF Writeup

## Challenge Overview

We are given a fictional scenario: the Republic of Meridia’s canal-defence signals office issued six ECDSA-signed orders during an entropy incident. An adversary may have read a sealed standing order and used it to divert logistics. We must recover the sealed order token (a `CSCTF{...}` flag) from `sealed-orders.der` and the accompanying case note.

The bundle structure is:

```text
SignetBundle ::= SEQUENCE {
  version INTEGER,                         -- exactly 1
  signer SubjectPublicKeyInfo,             -- RFC 5480 EC SPKI
  orders SEQUENCE OF SignedOrder,          -- exactly six, seq 0..5
  seal SealedOrder
}
SignedOrder ::= SEQUENCE {
  seq INTEGER,
  message OCTET STRING,                    -- exact signed bytes
  signature ECDSA-Sig-Value
}
ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
SealedOrder ::= SEQUENCE {
  salt OCTET STRING,                       -- 16 bytes
  nonce OCTET STRING,                      -- 12 bytes
  ciphertext OCTET STRING,
  tag OCTET STRING                         -- 16 bytes
}
```

The curve is secp256k1, hash SHA-256, and signatures are raw (no low-s normalization). The sealed order uses HKDF-SHA-256 with `IKM = I2OSP(d, 32)` and AES-256-GCM. The plaintext is the flag.

## The Vulnerability

The entropy sampler stopped. During the fault, each consecutive signing operation consumed the next temporary scalar-register value. Its update was the same additive stride modulo the curve order \(n\). In other words, the nonces used in the six ECDSA signatures form an arithmetic progression:

\[
k_i = k_0 + i \cdot \Delta \pmod{n}
\]

for \(i = 0,1,\ldots,5\), where \(\Delta\) is an unknown constant stride. The starting value \(k_0\) and the stride \(\Delta\) are not logged.

In ECDSA, each signature satisfies:

\[
k_i = s_i^{-1} (z_i + r_i d) \pmod{n}
\]

where:

- \(z_i = \text{int\_be}(\text{SHA-256}(m_i)) \bmod n\)
- \(d\) is the private key
- \(r_i, s_i\) are the signature components

Because the nonces are linearly related, we can eliminate the unknown \(k_0\) and \(\Delta\) and solve for \(d\) using three consecutive signatures.

## Mathematical Recovery of the Private Key

Let \(u_i = s_i^{-1} \bmod n\). Then:

\[
k_i = u_i (z_i + r_i d) \pmod{n}
\]

The linear progression condition \(k_{i+2} - 2k_{i+1} + k_i \equiv 0 \pmod{n}\) gives:

\[
u_{i+2}(z_{i+2} + r_{i+2} d) - 2u_{i+1}(z_{i+1} + r_{i+1} d) + u_i(z_i + r_i d) \equiv 0 \pmod{n}
\]

Collecting terms with \(d\):

\[
d \cdot \bigl( u_{i+2} r_{i+2} - 2u_{i+1} r_{i+1} + u_i r_i \bigr)
\equiv
- \bigl( u_{i+2} z_{i+2} - 2u_{i+1} z_{i+1} + u_i z_i \bigr) \pmod{n}
\]

So:

\[
d \equiv
\frac{u_{i+2} z_{i+2} - 2u_{i+1} z_{i+1} + u_i z_i}
     {2u_{i+1} r_{i+1} - u_i r_i - u_{i+2} r_{i+2}}
\pmod{n}
\]

Using signatures \(i=0,1,2\) (or any consecutive triple) yields \(d\). We can then verify by checking that the nonce differences \(k_{i+1} - k_i\) are constant for all \(i\).

## Solution Steps

1. **Parse the DER bundle** — extract the six `(message, r, s)` triples and the sealed order components (`salt`, `nonce`, `ciphertext`, `tag`). Ensure dispatch sequence order `0..5`.
2. **Compute \(z_i\)** for each message: `int_be(SHA-256(message_i)) mod n`.
3. **Recover \(d\)** using the formula above with signatures 0,1,2. Verify that the derived public key matches the one in the SPKI.
4. **Derive the AES key**:
   - `IKM = d.to_bytes(32, 'big')`
   - `key = HKDF-SHA-256(IKM, salt=salt, info=b"CSCTF26/TheSignet/v1/standing-order", length=32)`
5. **Decrypt** the ciphertext with AES-256-GCM using the given nonce, ciphertext, tag, and empty AAD.
6. The plaintext is the complete `CSCTF{...}` token.

## Solver Script

Save as `solve_signet.py` and run with the DER file as argument.

```python
#!/usr/bin/env python3
import sys, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EXPECTED_SPKI_SHA256 = (
    "1c6b38a86c3ff8b1d295e02b884c457da537767b5fdf063cf6d7d733b683a6b3"
)
INFO = b"CSCTF26/TheSignet/v1/standing-order"


def read_tlv(buf, off=0):
    start = off
    tag = buf[off]
    off += 1
    lb = buf[off]
    off += 1

    if lb & 0x80:
        nb = lb & 0x7F
        if nb == 0:
            raise ValueError("indefinite length not allowed")
        length = int.from_bytes(buf[off:off + nb], "big")
        off += nb
    else:
        length = lb

    value = buf[off:off + length]
    if len(value) != length:
        raise ValueError("truncated DER value")
    off += length
    return (tag, value, buf[start:off]), off


def children(node):
    tag, value, _ = node
    if not (tag & 0x20):
        raise ValueError("expected constructed DER node")
    out = []
    off = 0
    while off < len(value):
        child, off = read_tlv(value, off)
        out.append(child)
    return out


def as_int(node):
    tag, value, _ = node
    if tag != 0x02:
        raise ValueError("expected INTEGER")
    return int.from_bytes(value, "big", signed=False)


def main(path):
    der = open(path, "rb").read()

    bundle, off = read_tlv(der)
    if off != len(der):
        raise ValueError("trailing bytes after bundle")
    if bundle[0] != 0x30:
        raise ValueError("bundle is not a SEQUENCE")

    top = children(bundle)
    version = as_int(top[0])
    signer = top[1]
    orders = top[2]
    seal = top[3]

    assert version == 1

    fp = hashlib.sha256(signer[2]).hexdigest()
    print("SPKI SHA-256:", fp)
    if fp != EXPECTED_SPKI_SHA256:
        print("WARNING: fingerprint does not match case note", file=sys.stderr)

    olist = children(orders)
    if len(olist) != 6:
        raise ValueError("expected exactly six orders")

    seqs, msgs, rs, ss = [], [], [], []

    for o in olist:
        parts = children(o)
        seqs.append(as_int(parts[0]))

        if parts[1][0] != 0x04:
            raise ValueError("message is not OCTET STRING")
        msgs.append(parts[1][1])

        sig = children(parts[2])
        if len(sig) != 2:
            raise ValueError("bad ECDSA signature")
        rs.append(as_int(sig[0]))
        ss.append(as_int(sig[1]))

    if seqs != list(range(6)):
        idx = sorted(range(6), key=lambda i: seqs[i])
        msgs = [msgs[i] for i in idx]
        rs = [rs[i] for i in idx]
        ss = [ss[i] for i in idx]

    z = [
        int.from_bytes(hashlib.sha256(m).digest(), "big") % n
        for m in msgs
    ]

    def inv(x):
        return pow(x % n, -1, n)

    u = [inv(s) for s in ss]

    def nonce(i, d):
        return (u[i] * (z[i] + rs[i] * d)) % n

    d = None

    for a in range(4):
        b, c = a + 1, a + 2
        num = (u[c] * z[c] - 2 * u[b] * z[b] + u[a] * z[a]) % n
        den = (2 * u[b] * rs[b] - u[a] * rs[a] - u[c] * rs[c]) % n

        if den == 0:
            continue

        cand = (num * inv(den)) % n
        diffs = [(nonce(i + 1, cand) - nonce(i, cand)) % n for i in range(5)]

        if len(set(diffs)) == 1:
            d = cand
            print(f"recovered d    = {d:#066x}")
            print(f"nonce stride   = {diffs[0]:#066x}")
            break

    if d is None:
        raise RuntimeError("could not recover d")

    pub = serialization.load_der_public_key(signer[2])
    priv = ec.derive_private_key(d, ec.SECP256K1())
    pn = priv.public_key().public_numbers()
    qn = pub.public_numbers()
    assert (pn.x, pn.y) == (qn.x, qn.y)
    print("public key matches recovered d")

    seal_parts = children(seal)
    if len(seal_parts) != 4:
        raise ValueError("bad SealedOrder")

    salt = seal_parts[0][1]
    nonce_bytes = seal_parts[1][1]
    ciphertext = seal_parts[2][1]
    tag = seal_parts[3][1]

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=INFO,
    ).derive(d.to_bytes(32, "big"))

    plaintext = AESGCM(key).decrypt(
        nonce_bytes,
        ciphertext + tag,
        b"",
    )

    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sealed-orders.der")
```

## Running the Solver

```bash
python3 -m pip install cryptography
python3 solve_signet.py sealed-orders.der
```

The script prints the recovered private key, the nonce stride, verifies the public key, and finally outputs the decrypted `CSCTF{...}` token.

## Conclusion

The challenge hinges on a faulty entropy source that produces ECDSA nonces in an arithmetic progression. By exploiting the linear relation between consecutive nonces, we recover the private key from three signatures, then use it to derive the HKDF key and decrypt the sealed order. The flag is the plaintext of that sealed order. The provided solver automates the entire process; given the missing `sealed-orders.der`, it will yield the exact token when run.