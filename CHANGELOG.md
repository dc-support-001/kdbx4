# Changelog

## 0.1.0

- Initial release. Pure-Dart KDBX4 reader/writer extracted from the Sesame PS
  app, built on PointyCastle + `xml`.
- Writes KDBX 4.0; reads KDBX 4.0/4.1. Argon2id (default) and AES-KDF.
- KAT-pinned primitive and format tests; reads real KeePassXC fixtures.
- Public API: `KdbxFile`, `KdbxDatabase`, `Credentials`, `Kdf`/`Argon2Kdf`/
  `AesKdf`, the `KdbxContent` model, `VarDictionary`, `sha256`/`sha512`,
  `secureRandomBytes`, and the KDBX exceptions.
