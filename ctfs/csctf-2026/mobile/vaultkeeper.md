# VaultKeeper APK — CTF Writeup

## Challenge Summary

We're given `vaultkeeper.apk` (2,413,853 bytes, SHA-256 `79559746ad419b219c88b362ff89b667993bad726e3b7109501b075c007de2ed`) and an authorization code `ZHUU-SANS-9XJN-QPCQ`. The objective is to recover a note hidden in the APK through offline static analysis — no installation or UI interaction required.

**Category:** Android Reverse Engineering  
**Flag location:** AES-GCM ciphertext stored in `R.string.flag_ciphertext_b64`, decrypted with a key derived from three inputs.

---

## TL;DR

The flag is decrypted by this pipeline (from `MainActivity`):

    key  = SHA-256( devicePart + archiveDigits + passcode )
    blob = Base64.decode(R.string.flag_ciphertext_b64)
    iv   = blob[0:12]
    ct   = blob[12:]
    flag = AES/GCM/NoPadding(key, iv).decrypt(ct)

Where:

| Input           | Value                       | Source                                              |
|-----------------|-----------------------------|-----------------------------------------------------|
| `devicePart`    | `KJSC-1C28DC7E-RECOVERY`    | First 8 hex chars of APK cert SHA-256, uppercased   |
| `archiveDigits` | 4-digit code                | Brute-forced (only 10,000 possibilities)            |
| `passcode`      | `ZHUU-SANS-9XJN-QPCQ`       | Provided in challenge description                   |

Because AES-GCM authenticates, wrong keys throw `AEADBadTagException` — giving us a perfect oracle to brute-force the 4-digit code.

---

## Step 1 — Setup & Decompile

Tools used:

    # jadx wrapper on Kali has a bug resolving relative paths
    # (it cd's into /usr/share/jadx/bin before exec'ing java)
    # so always use absolute paths for -d and input.
    jadx -d "$PWD/jadx-out" "$PWD/vaultkeeper.apk"

> **Note:** `jadx` reported `finished with errors, count: 6`. That's normal for obfuscated APKs — 6 methods failed to decompile, but everything needed for the challenge decompiled fine. If a required class is missing from jadx output, fall back to `apktool d` and read the Smali.

---

## Step 2 — Identify the Decryption Routine

Search the decompiled tree for the flag resource:

    grep -R "flag_ciphertext_b64" jadx-out

We find it in `MainActivity`, in the click handlers for both the **Scan** and **Archive** buttons. All three handlers contain identical decryption logic (a copy-pasted inner class). The essential code:

    String strA0        = A.c.a0(mainActivity);                            // devicePart
    String archiveCache = sharedPreferences.getString("archive_digits_cache", null);
    String passcode     = binding.etPasscode.getText().toString();        // user input

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] key = md.digest( (strA0 + archiveCache + passcode).getBytes(UTF_8) );

    byte[] blob = Base64.decode(getString(R.string.flag_ciphertext_b64), 0);
    byte[] iv   = blob[0..11];       // first 12 bytes
    byte[] ct   = blob[12..end];

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(DECRYPT_MODE, new SecretKeySpec(key, "AES"),
           new GCMParameterSpec(128, iv));
    String flag = new String(c.doFinal(ct), UTF_8);

The `stage1_complete` / `stage2_complete` gates are UI-only — irrelevant offline.

---

## Step 3 — Recover `devicePart`

`A.c.a0(Context)` hashes the **APK signing certificate**:

    public static String a0(Context context) {
        byte[] d = MessageDigest.getInstance("SHA-256")
            .digest(context.getPackageManager()
                            .getPackageInfo(context.getPackageName(), 64)
                            .signatures[0].toByteArray());
        String s = K0.b.w0(d, H0.b.f387c).substring(0, 8).toUpperCase(Locale.ROOT);
        return "KJSC-" + s + "-RECOVERY";
    }

`K0.b.w0` maps each byte through a formatter; `H0.b.b(...)` in the constructor branch `1` is:

    return String.format("%02x", Arrays.copyOf(new Object[]{Byte.valueOf(b)}, 1));

So `w0` is just a **lowercase hex encoder**. Therefore `devicePart` depends only on the cert digest.

Get the cert digest:

    apksigner verify --print-certs vaultkeeper.apk | grep "SHA-256"
    # or
    keytool -printcert -jarfile vaultkeeper.apk | grep SHA256

Result:

    Signer #1 certificate SHA-256 digest: 1c28dc7e5ab079ffa0f014a0fefd11c7bf673e5d0d912c4c80ebd210818894d6

First 8 hex chars, uppercased:

    devicePart = KJSC-1C28DC7E-RECOVERY

---

## Step 4 — Recover `archiveDigits`

Search where the value is written:

    grep -R -n "archive_digits_cache" jadx-out/sources

    com/vaultkeeper/ArchiveActivity.java:70    putString("archive_digits_cache", string).apply();
    com/vaultkeeper/MainActivity.java:250      getString("archive_digits_cache", null);
    ...

In `ArchiveActivity`, the value comes from `EditText` `etDigits` and is validated:

    if (string.length() != 4) { ... "enter exactly 4 digits"; }
    for (int i = 0; i < string.length(); i++) {
        if (!Character.isDigit(string.charAt(i))) { ... "enter exactly 4 digits"; }
    }
    getSharedPreferences("vaultkeeper_state", 0).edit()
        .putString("archive_digits_cache", string).apply();

So **`archiveDigits` is a 4-digit number** — `0000` to `9999`. Only 10,000 candidates. No need to find it statically.

---

## Step 5 — Extract the Ciphertext

From `res/values/strings.xml`:

    <string name="flag_ciphertext_b64">5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/</string>

---

## Step 6 — Brute-Force + Decrypt

Because AES-GCM authenticates the ciphertext, any wrong key throws `AEADBadTagException`. This gives us a cheap oracle: only the correct 4-digit archive code will produce plaintext.

    import base64, hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ct_b64 = ("5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj"
              "+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/")

    device_part = "KJSC-1C28DC7E-RECOVERY"
    passcode    = "ZHUU-SANS-9XJN-QPCQ"

    blob = base64.b64decode(ct_b64 + "=" * (-len(ct_b64) % 4))
    iv, ct = blob[:12], blob[12:]

    for n in range(10000):
        digits = f"{n:04d}"
        key = hashlib.sha256(
            (device_part + digits + passcode).encode("utf-8")
        ).digest()
        try:
            pt = AESGCM(key).decrypt(iv, ct, None)
            print("FOUND archiveDigits =", digits)
            print("FLAG:", pt.decode("utf-8"))
            break
        except Exception:
            pass

PyCryptodome equivalent:

    from Crypto.Cipher import AES
    for n in range(10000):
        digits = f"{n:04d}"
        key = hashlib.sha256((device_part + digits + passcode).encode()).digest()
        try:
            c = AES.new(key, AES.MODE_GCM, nonce=iv)
            pt = c.decrypt_and_verify(ct[:-16], ct[-16:])
            print(digits, pt.decode())
            break
        except ValueError:
            pass

The loop finds the 4-digit archive code and prints the flag.

---

## Appendix — Solving Without Brute-Force

If you want to avoid brute-forcing, replicate the app's UI flow:

1. Launch the app, complete **Stage 1** (archival code) to satisfy `stage1_complete`.
2. The **Archive Activity** lets you enter the 4-digit code and shows `archive_key: XXXX...` — the HMAC-derived key for Stage 2 (`broadcast this to RecoveryStage2Receiver as the "archive_key" extra`).
3. Complete **Stage 2** to satisfy `stage2_complete`.
4. Return to the main screen, paste `ZHUU-SANS-9XJN-QPCQ` into the passcode field, click **Unlock**.

This is exactly what the challenge said you *don't* need to do — static analysis is faster and doesn't require a physical device with the correct signing cert installed.

---

## Key Takeaways

- **Never trust the gate.** The `stage1_complete` / `stage2_complete` `SharedPreferences` flags do nothing except unlock a UI path. The decryption inputs are all derivable offline.
- **Auth tags are oracles.** AES-GCM is authenticated: `AEADBadTagException` is a perfect "wrong key" signal. When the unknown key material has low entropy (10⁴ here), brute force is trivial.
- **Look at the cert.** `context.getPackageManager().getPackageInfo(..., 64).signatures[0]` is a common anti-tamper trick. If you're offline, `apksigner verify --print-certs` recovers the same digest.
- **Copy-paste code is a gift.** `MainActivity` contains the same decryption block three times. Reading any one of them tells you the full pipeline.
- **jadx errors ≠ failed decompilation.** `finished with errors, count: 6` only means a handful of methods couldn't be decompiled. The classes you need are almost always present. Fall back to `apktool` + Smali if a specific one is missing.