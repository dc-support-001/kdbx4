import 'dart:typed_data';

import '../crypto/aes_cbc.dart';
import '../crypto/chacha20.dart';
import '../kdbx_exceptions.dart';

/// Outer-cipher UUIDs (header CipherID).
final Uint8List cipherAes256 = Uint8List.fromList([
  0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, //
  0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
]);
final Uint8List cipherChaCha20 = Uint8List.fromList([
  0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, //
  0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
]);

/// The KDBX outer cipher, selected by header CipherID. AES-256 uses CBC +
/// PKCS7; ChaCha20 is a stream cipher (no padding). Sesame writes AES-256;
/// ChaCha20 is supported for foreign files.
class OuterCipher {
  /// Encrypt the (already compressed) payload.
  static Uint8List encrypt(
      Uint8List cipherId, Uint8List key, Uint8List iv, Uint8List plain) {
    if (_eq(cipherId, cipherAes256)) {
      return aesCbc(key, iv, pkcs7Pad(plain), encrypt: true);
    }
    if (_eq(cipherId, cipherChaCha20)) {
      return chacha20(key, iv, plain);
    }
    throw UnsupportedCipherException(cipherId);
  }

  /// Decrypt to the (still compressed) payload.
  static Uint8List decrypt(
      Uint8List cipherId, Uint8List key, Uint8List iv, Uint8List cipher) {
    if (_eq(cipherId, cipherAes256)) {
      return pkcs7Unpad(aesCbc(key, iv, cipher, encrypt: false));
    }
    if (_eq(cipherId, cipherChaCha20)) {
      return chacha20(key, iv, cipher);
    }
    throw UnsupportedCipherException(cipherId);
  }
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
