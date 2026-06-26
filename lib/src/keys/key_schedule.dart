import 'dart:typed_data';

import '../crypto/hashes.dart';
import '../io/byte_writer.dart';

/// KDBX4 key schedule: from the master seed (header) and the KDF's transformed
/// key, derive the data-encryption key and the HMAC key material.

/// AES-256 data-encryption key: `SHA-256(masterSeed ‖ transformedKey)`.
Uint8List finalKey(Uint8List masterSeed, Uint8List transformedKey) =>
    sha256((ByteWriter()
          ..bytes(masterSeed)
          ..bytes(transformedKey))
        .toBytes());

/// 64-byte base for the block-HMAC keys:
/// `SHA-512(masterSeed ‖ transformedKey ‖ 0x01)`.
Uint8List hmacBaseKey(Uint8List masterSeed, Uint8List transformedKey) =>
    sha512((ByteWriter()
          ..bytes(masterSeed)
          ..bytes(transformedKey)
          ..u8(0x01))
        .toBytes());

/// Per-block HMAC key: `SHA-512(u64LE(blockIndex) ‖ hmacBase)`.
Uint8List blockHmacKey(Uint8List hmacBase, int blockIndex) =>
    sha512((ByteWriter()
          ..u64(blockIndex)
          ..bytes(hmacBase))
        .toBytes());

/// The header is authenticated with block index `0xFFFFFFFFFFFFFFFF`.
Uint8List headerHmacKey(Uint8List hmacBase) => sha512((ByteWriter()
      ..bytes(const [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
      ..bytes(hmacBase))
    .toBytes());
