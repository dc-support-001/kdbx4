/// kdbx4 — a pure-Dart reader/writer for the **KDBX4** (KeePass) database format.
///
/// Built only on [`pointycastle`](https://pub.dev/packages/pointycastle) for the
/// cryptographic primitives (AES, Argon2id/d, ChaCha20, Salsa20, SHA, HMAC) plus
/// [`xml`](https://pub.dev/packages/xml); this library implements the KDBX4
/// *container format* on top of them. No Flutter dependency — usable in Flutter
/// apps, Dart servers, and CLIs.
///
/// Writes KDBX 4.0; reads KDBX 4.0/4.1. (KDBX 3.x is intentionally unsupported.)
///
/// Typical use:
/// ```dart
/// final db = KdbxDatabase.create(
///   content: KdbxContent(meta: KdbxMeta(databaseName: 'My vault'),
///                        root: KdbxGroup(uuid: secureRandomBytes(16), name: 'Root')),
///   kdf: Argon2Kdf.sesameDefault(secureRandomBytes(32)),
///   credentials: Credentials.password('correct horse'),
/// );
/// final bytes = KdbxFile.serialize(db);                 // -> Uint8List, write to a file
/// final reopened = KdbxFile.open(bytes: bytes,
///     credentials: Credentials.password('correct horse'));
/// ```
///
/// See `SECURITY.md` for the security design, guarantees, and limitations.
library;

export 'src/kdbx_file.dart'
    show KdbxFile, KdbxDatabase, compressionNone, compressionGzip;
export 'src/kdbx_exceptions.dart';
export 'src/keys/credentials.dart' show Credentials;
export 'src/keys/kdf.dart' show Kdf, Argon2Kdf, AesKdf;
export 'src/crypto/argon2.dart' show Argon2Type;
export 'src/content/kdbx_model.dart'
    show
        KdbxContent,
        KdbxMeta,
        KdbxGroup,
        KdbxEntry,
        KdbxTimes,
        KdbxStringValue;
export 'src/format/var_dictionary.dart' show VarDictionary;
export 'src/crypto/hashes.dart' show sha256, sha512;
export 'src/crypto/random.dart' show secureRandomBytes;
