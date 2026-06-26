# kdbx4 security self-audit checklist

A reviewer-style checklist for the **kdbx4** KDBX4 engine — the bespoke surface
that warrants security review. The cryptographic *primitives* are PointyCastle and
out of scope here. Each item states **what to verify**, the **current status**, and
the **evidence / gaps**. Re-run before any release. All paths are relative to this
repo (sources under `lib/src/`).

> Consuming apps have their own surface this checklist does **not** cover — how
> they orchestrate locking, what (plaintext) labels they place in
> `PublicCustomData`, their transport, etc. That is the app's responsibility.

Status key: ✅ holds · ⚠️ holds with a caveat · ⬜ todo / not yet evidenced.

## 1. Primitives & randomness

- ✅ **No hand-rolled primitives.** AES/Argon2/ChaCha20/Salsa20/SHA/HMAC are all
  PointyCastle; `src/crypto/*.dart` are thin parameter wrappers (~180 LOC).
- ✅ **CSPRNG for all key material.** `src/crypto/random.dart` uses `Random.secure()`
  for every security-relevant value (seeds, IVs, nonces, salts, inner-stream keys).
  `grep -rn "Random(" lib/` shows only `Random.secure()`.
- ✅ **Primitive correctness pinned to KATs.** `test/crypto/*`. _Gap (⬜):_ expand
  to the full NIST/RFC vector sets, not just representative vectors.

## 2. Key derivation & schedule

- ✅ **Key bound to the credential, not the binary.** Data key derives from the
  passcode via Argon2id (`keys/kdf.dart`, default 64 MiB / t=3 / p=1); no key
  constant in the library.
- ✅ **Composite key per spec.** `SHA-256` of concatenated 32-byte components;
  password = `SHA-256(utf8)` (`keys/credentials.dart`). Components validated 32 B.
- ✅ **Key schedule matches KeePass KDBX4.** `dataKey = SHA-256(seed‖transformed)`;
  `hmacBase = SHA-512(seed‖transformed‖0x01)`; block key
  `SHA-512(u64LE(idx)‖hmacBase)`; header uses index `0xFFFF…FF`
  (`keys/key_schedule.dart`). Cross-checked by KeePassXC fixtures.
- ✅ **Argon2 parameters come from the file's own header on read** (so foreign
  files open), and are written at the configured default on write.

## 3. Authenticated encryption / integrity

- ✅ **Encrypt-then-MAC, verified before decrypt.** `kdbx_file.dart` `open` checks
  the header SHA-256 (integrity) and header HMAC (authentication) *before*
  decrypting; the body is read via the HMAC block stream
  (`payload/hmac_block_stream.dart`).
- ✅ **Wrong passcode ≠ corruption.** Header-HMAC mismatch →
  `WrongCredentialsException`; SHA-256 mismatch → `KdbxIntegrityException`.
- ✅ **No padding oracle.** PKCS#7 unpad (`crypto/aes_cbc.dart`) runs only on
  already-authenticated plaintext (MAC checked first), so unpad errors are not
  attacker-observable on chosen ciphertext.
- ✅ **Tamper-evidence covers the header**, including `PublicCustomData` — it is
  integrity-protected though **not encrypted** (plaintext; callers must not store
  sensitive data there).
- ⬜ **Fuzz the parser.** No fuzzing yet of malformed/adversarial `.kdbx` (outer
  header TLVs, VarDictionary, inner header, block-stream lengths, XML). Add a fuzz
  target asserting *no crash / no OOM / clean exception* on garbage input.

## 4. IV / nonce / salt uniqueness

- ✅ **Fresh per save.** `kdbx_file.dart` `write` regenerates master seed (32 B),
  cipher IV/nonce (16 B AES / 12 B ChaCha), and inner-stream key (64 B) on every
  serialize — even when re-saving with the cached transformed key — so no IV reuse
  under a stable key.
- ✅ **Inner random stream** (ChaCha20/Salsa20 field protection) keyed from the
  fresh per-save inner-stream key (`content/inner_random_stream.dart`).

## 5. Constant-time comparison

- ✅ Header SHA/HMAC comparison is length-checked constant-time
  (`kdbx_file.dart:_eq`). _Verify no `==`/`listEquals` on key/MAC bytes._ Callers
  doing their own passcode/key comparisons should likewise be constant-time.

## 6. Memory hygiene

- ⚠️ **Key material is zeroizable.** `Credentials.zeroize()` wipes the composite-key
  components; `KdbxDatabase.transformedKey` can be wiped (`fillRange(0,…,0)`).
  **Caveat:** Dart `String`s are immutable + GC'd, so plaintext secrets passing
  through `String`s (e.g. `KdbxStringValue.value`) cannot be reliably wiped.
  _Consider (⬜):_ minimize `String` lifetime on value hot paths.
- ℹ️ The library exposes the zeroize hooks; **dropping the `KdbxDatabase` reference
  on lock is the caller's responsibility** (lifecycle lives in the consuming app).

## 7. Format robustness & versioning

- ✅ **KDBX 4 only**, by design — major-version check rejects 3.x and others
  (`format/outer_header.dart`).
- ✅ Reads 4.0/4.1, writes 4.0.
- ✅ Mandatory outer-header fields validated present on parse; unknown TLVs ignored
  safely.
- ⬜ Add explicit bounds/overflow review for `io/byte_reader.dart` on
  attacker-controlled lengths (covered indirectly today; make it a fuzz assertion).

## 8. Interop & regression evidence

- ✅ Reads real **KeePassXC-produced fixtures** (`test/fixtures/`) in the format and
  content round-trip tests.
- ⬜ Add a **generative** interop test that round-trips against the `keepassxc-cli`
  binary (write here → open in KeePassXC → re-read), not just static fixtures.
- ⬜ Widen fixtures: a KDBX **4.1** file from KeePass 2.x; AES-KDF (not just
  Argon2); a ChaCha20-cipher file.

## Quick verification commands

```bash
dart test                                      # KATs + format + smoke
grep -rn "Random(" lib/                        # expect only Random.secure()
grep -rn "==" lib/src/ | grep -i "hmac\|mac\|key\|sha"   # spot non-constant-time compares
dart pub publish --dry-run                     # packaging sanity
```

## Top gaps to close (priority order)

1. ⬜ **Parser fuzzing** of malformed `.kdbx` (no crash/OOM). *Highest value — the
   bespoke surface most likely to hide a bug.*
2. ⬜ **Widen interop/KAT fixtures** (KDBX 4.1, AES-KDF, ChaCha20, full vector sets;
   a generative `keepassxc-cli` round-trip).
3. ⬜ **Bug bounty + a scoped external review** of the format layer. _(Publishing to
   pub.dev / open-sourcing: **done** — `0.1.0`.)_
4. ⬜ Reduce plaintext-`String` lifetime on value hot paths.
