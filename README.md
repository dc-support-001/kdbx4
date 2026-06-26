# kdbx4

A **pure-Dart reader/writer for the KDBX4 (KeePass) database format.**

- Built only on [`pointycastle`](https://pub.dev/packages/pointycastle) for
  cryptographic primitives (AES, Argon2id/d, ChaCha20, Salsa20, SHA, HMAC) and
  [`xml`](https://pub.dev/packages/xml). This library implements the KDBX4
  *container format* on top of those vetted primitives — it does not roll its own
  crypto.
- **No Flutter dependency.** Works in Flutter apps, Dart servers, and CLIs.
- Writes KDBX **4.0**; reads KDBX **4.0 / 4.1**. KDBX 3.x is intentionally
  unsupported.
- Default KDF: **Argon2id** (64 MiB, t=3, p=1). AES-KDF supported for reading
  foreign files.
- Round-trip interoperable with KeePassXC.

## Scope

kdbx4 deliberately does **one thing** — the KDBX4 format — and keeps a small,
focused surface. All cryptographic primitives are delegated to the established
[PointyCastle](https://pub.dev/packages/pointycastle) library; this package
implements only the container format on top. The engine is **extracted from a
shipping app**, is **KAT-pinned**, and is **KeePassXC-interop-tested**. If you
need KDBX 3.x support or a broader KeePass API, other Dart packages cover that —
this one optimizes for a minimal, auditable KDBX4 reader/writer.

## Install

```yaml
dependencies:
  kdbx4: ^0.1.0
```

## Usage

```dart
import 'package:kdbx4/kdbx4.dart';

void main() {
  final entry = KdbxEntry(uuid: secureRandomBytes(16), strings: {
    'Title': const KdbxStringValue('GitHub'),
    'UserName': const KdbxStringValue('octocat'),
    'Password': const KdbxStringValue('s3cr3t', protected: true),
  });
  final content = KdbxContent(
    meta: KdbxMeta(databaseName: 'My vault'),
    root: KdbxGroup(uuid: secureRandomBytes(16), name: 'Root', entries: [entry]),
  );

  final db = KdbxDatabase.create(
    content: content,
    kdf: Argon2Kdf.sesameDefault(secureRandomBytes(32)),
    credentials: Credentials.password('correct horse battery staple'),
  );

  final bytes = KdbxFile.serialize(db);          // -> Uint8List; write to a .kdbx file

  final reopened = KdbxFile.open(                // throws WrongCredentialsException on a bad passcode
    bytes: bytes,
    credentials: Credentials.password('correct horse battery staple'),
  );
  print(reopened.content.meta.databaseName);
}
```

See [`example/kdbx4_example.dart`](example/kdbx4_example.dart).

## Design

The library is **bytes ⇄ model**: you provide/receive file bytes, and it parses
or serializes the KDBX container. It performs no file I/O itself, so it stays
portable. Authentication is checked *before* decryption (encrypt-then-MAC: the
header SHA-256 and HMAC, then the HMAC block stream), so corruption and wrong
passcodes are distinguished and there is no padding oracle.

## Security

See [`SECURITY.md`](SECURITY.md) for the crypto design, guarantees, known
limitations, and how to report a vulnerability.

## Status

`0.1.0` — pre-1.0; the public API may still change. The KDBX engine is
KAT-pinned and interop-tested. See `CHANGELOG.md`.

## License

MIT — see [`LICENSE`](LICENSE).
