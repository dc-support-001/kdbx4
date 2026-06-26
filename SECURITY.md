# Security

`kdbx4` implements the KDBX4 container format. It is written to be verifiable
against the source — file paths below refer to `lib/src/`.

## Primitives — a vetted library, not hand-rolled

All cryptographic primitives come from
[PointyCastle](https://pub.dev/packages/pointycastle). The wrappers in
`lib/src/crypto/` only wire parameters and are pinned to known-answer test (KAT)
vectors:

| Primitive | Source |
|---|---|
| AES-256-CBC / AES-ECB (legacy read KDF) | `CBCBlockCipher`/`ECBBlockCipher(AESEngine())` |
| Argon2id / Argon2d | `Argon2BytesGenerator` |
| ChaCha20 (RFC 8439) / Salsa20 | `ChaCha7539Engine` / `Salsa20Engine` |
| SHA-256 / SHA-512 / HMAC-SHA-256 | `SHA256Digest` / `SHA512Digest` / `HMac` |
| CSPRNG | `Random.secure()` (platform CSPRNG, `crypto/random.dart`) |

This library implements only the **KDBX4 format** on top: headers, key schedule,
the HMAC block stream, the inner random stream, gzip, and the XML content
(`format/`, `keys/`, `payload/`, `content/`, `kdbx_file.dart`).

## Properties

- **Key bound to the credential**, derived via Argon2id (default 64 MiB, t=3,
  p=1); KDF parameters are read from the file header. No key is embedded in the
  library.
- **Key schedule** follows the KeePass KDBX4 spec
  (`dataKey = SHA-256(masterSeed ‖ transformedKey)`;
  `hmacBase = SHA-512(masterSeed ‖ transformedKey ‖ 0x01)`).
- **Authenticated before decryption.** On `open`, the header SHA-256 and header
  HMAC are verified, and the body is read through the HMAC block stream, before
  any plaintext is produced. A wrong passcode fails the header HMAC
  (`WrongCredentialsException`); corruption fails the SHA-256
  (`KdbxIntegrityException`). PKCS#7 unpadding therefore runs only on
  already-authenticated plaintext — not a padding oracle.
- **Fresh randomness per write.** Every `serialize` generates a new master seed,
  cipher IV/nonce, and inner-stream key from the CSPRNG (no IV reuse under a
  stable key).

## Known limitations

- **No independent third-party audit yet.** Primitives are vetted (PointyCastle)
  and the format layer is KAT- and KeePassXC-interop-tested, but the format layer
  has not had an external audit.
- **Memory zeroization is best-effort.** `Credentials.zeroize()` and the
  transformed-key wipe clear byte buffers, but Dart `String`s are immutable and
  garbage-collected, so plaintext that passes through `String`s cannot be reliably
  wiped.
- **KDBX 3.x is unsupported** by design (major version 4 only).
- Brute-force resistance is bounded by passcode strength and the Argon2
  parameters.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **support@datacanals.com**
rather than opening a public issue. Include reproduction steps and the affected
version. A formal disclosure policy and bug bounty are planned.
