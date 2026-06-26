# `kdbx4` engine security self-audit checklist

> The KDBX engine has been extracted from this app into the standalone **`kdbx4`**
> package (a `../kdbx4` path dependency). This checklist audits **that package** —
> all `lib/...`, `src/...`, and `test/...` paths below are relative to the `kdbx4`
> repo (sources under `kdbx4/lib/src/`). A copy of this checklist also lives in the
> `kdbx4` repo. The app-side files it still references (`kdbx_repository.dart`) are
> in this repo's `lib/repository/`.

A reviewer-style checklist for the KDBX engine — the bespoke surface that warrants
security review (the cryptographic *primitives* are PointyCastle and out of
scope here). Each item states **what to verify**, the **current status**, and the
**evidence / gaps**. Re-run before any release that touches the `kdbx4` engine,
and use it to scope an external review.

Status key: ✅ holds · ⚠️ holds with a caveat · ⬜ todo / not yet evidenced.

## 1. Primitives & randomness

- ✅ **No hand-rolled primitives.** AES/Argon2/ChaCha20/Salsa20/SHA/HMAC are all
  PointyCastle; `src/crypto/*.dart` are thin parameter wrappers (~180 LOC).
- ✅ **CSPRNG for all key material.** `src/crypto/random.dart` uses `Random.secure()`
  for every security-relevant value (seeds, IVs, nonces, salts, inner-stream
  keys). Within the `kdbx4` package, `grep -rn "Random(" lib/` shows only
  `Random.secure()`. _(The host app separately has two **non-cryptographic**
  `Random()` uses — a perf/debug screen and the mDNS probe instance name — but
  those are outside this package.)_
- ✅ **Primitive correctness pinned to KATs.** `test/crypto/*`. _Gap (⬜):_
  expand to the full NIST/RFC vector sets, not just representative vectors.

## 2. Key derivation & schedule

- ✅ **Key bound to the user, not the binary.** Data key derives from the master
  passcode via Argon2id (`keys/kdf.dart`, default 64 MiB / t=3 / p=1); no key
  constant in the app.
- ✅ **Composite key per spec.** `SHA-256` of concatenated 32-byte components;
  password = `SHA-256(utf8)` (`keys/credentials.dart`). Components validated to be
  32 bytes.
- ✅ **Key schedule matches KeePass KDBX4.** `dataKey = SHA-256(seed‖transformed)`;
  `hmacBase = SHA-512(seed‖transformed‖0x01)`; block key
  `SHA-512(u64LE(idx)‖hmacBase)`; header uses index `0xFFFF…FF`
  (`keys/key_schedule.dart`). Cross-checked by KeePassXC interop.
- ✅ **Argon2 parameters come from the file's own header on read** (so foreign
  files open), and are written at the Sesame default on write.

## 3. Authenticated encryption / integrity

- ✅ **Encrypt-then-MAC, verified before decrypt.** `kdbx_file.dart:open` checks
  the header SHA-256 (integrity) and header HMAC (authentication) *before*
  decrypting; the body is read via the HMAC block stream
  (`payload/hmac_block_stream.dart`).
- ✅ **Wrong passcode ≠ corruption.** Header-HMAC mismatch →
  `WrongCredentialsException`; SHA-256 mismatch → `KdbxIntegrityException`.
- ✅ **No padding oracle.** PKCS#7 unpad (`crypto/aes_cbc.dart`) runs only on
  already-authenticated plaintext (the MAC is checked first), so unpad errors are
  not attacker-observable on chosen ciphertext.
- ✅ **Tamper-evidence covers the header**, including `PublicCustomData` (the
  plaintext vault name) — it is integrity-protected though not encrypted.
- ⬜ **Fuzz the parser.** No fuzzing yet of malformed/adversarial `.kdbx` (outer
  header TLVs, VarDictionary, inner header, block-stream lengths, XML). Add a
  fuzz target asserting *no crash / no OOM / clean exception* on garbage input.

## 4. IV / nonce / salt uniqueness

- ✅ **Fresh per save.** `kdbx_file.dart:write` regenerates master seed (32 B),
  cipher IV/nonce (16 B AES / 12 B ChaCha), and inner-stream key (64 B) on every
  serialize — even when re-saving with the cached transformed key — so no IV reuse
  under a stable key.
- ✅ **Inner random stream** (ChaCha20/Salsa20 field protection) keyed from the
  fresh per-save inner-stream key (`content/inner_random_stream.dart`).

## 5. Constant-time comparison

- ✅ Secret-material comparisons are length-checked constant-time:
  `kdbx_file.dart:_eq` (header SHA/HMAC), `kdbx_repository.dart:_constantTimeEq`
  (passcode verify / re-key). _Verify no `==`/`listEquals` on key/MAC bytes._

## 6. Memory hygiene

- ⚠️ **Key material zeroized on lock.** `Credentials.zeroize()` and
  `KdbxDatabase.transformedKey.fillRange(0,…,0)` on `close()`. **Caveat:** Dart
  `String`s are immutable + GC'd, so plaintext secrets passing through `String`s
  cannot be reliably wiped — documented in `SECURITY.md`. _Consider (⬜):_ minimize
  `String` lifetime for plaintext values; prefer byte buffers on hot paths.
- ✅ Lock drops the decrypted DB reference so plaintext is no longer reachable.

## 7. Format robustness & versioning

- ✅ **KDBX 4 only**, by design — major-version check rejects 3.x and others
  (`format/outer_header.dart`).
- ✅ Reads 4.0/4.1, writes 4.0.
- ✅ Mandatory outer-header fields validated present on parse; unknown TLVs
  ignored safely.
- ⬜ Add explicit bounds/overflow checks review for `io/byte_reader.dart` on
  attacker-controlled lengths (covered indirectly today; make it a fuzz assertion).

## 8. Interop & regression evidence

- ✅ Round-trip against the real KeePassXC binary (`test/interop/` in the kdbx4 repo, or the app-level `test/kdbx/interop/`).
- ⬜ Add fixtures: a KDBX **4.1** file from KeePass 2.x; files using AES-KDF (not
  just Argon2); a ChaCha20-cipher file — to widen read coverage.

## 9. Transport (informational — the app's `lib/sync/`, not the `kdbx4` engine)

Out of this checklist's scope but adjacent: per-session TLS + commit-reveal 6-digit
SAS with cert-bound code (`sync_cert.dart`, `sync_handshake.dart`). Reviewed
separately; see `doc/sync_design.md`.

## Quick verification commands

```bash
# In the kdbx4 repo (the engine):
dart test                                      # KATs + format + smoke
grep -rn "Random(" lib/                        # expect only Random.secure()
grep -rn "==" lib/src/ | grep -i "hmac\|mac\|key\|sha"   # spot non-constant-time compares

# In this app repo (the adapter + app-level interop):
flutter test test/kdbx/                        # repository/mapping integration tests
flutter test --tags interop                    # app-level KeePassXC round-trip (needs KeePassXC)
```

## Top gaps to close (priority order)

1. ⬜ **Parser fuzzing** of malformed `.kdbx` (no crash/OOM). *Highest value —
   it's the bespoke surface most likely to hide a bug.*
2. ⬜ **Widen interop/KAT fixtures** (KDBX 4.1, AES-KDF, ChaCha20, full vector sets).
3. ⬜ **Publish / open-source the `kdbx4` package + bug bounty**, then a **scoped
   external review** of the format layer.
4. ⬜ Reduce plaintext-`String` lifetime on value hot paths.
