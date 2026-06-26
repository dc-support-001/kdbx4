import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'hashes.dart';

/// Legacy KDBX **AES-KDF** key transform (read-path only).
///
/// KeePass's pre-Argon2 KDF: AES-256 in ECB encrypts the 32-byte composite key
/// — both 16-byte halves — under [seed] as the key, repeated [rounds] times,
/// then SHA-256 of the result. We must support it because KeePassXC's CLI
/// `db-create` still defaults to AES-KDF (Appendix 2 finding). New Sesame vaults
/// use Argon2id; this only reads foreign files.
Uint8List aesKdfTransform(Uint8List key32, Uint8List seed32, int rounds) {
  final out = Uint8List.fromList(key32);
  final cipher = ECBBlockCipher(AESEngine())..init(true, KeyParameter(seed32));
  for (var r = 0; r < rounds; r++) {
    // ECB has no chaining state, so repeated processBlock calls are independent.
    cipher.processBlock(out, 0, out, 0);
    cipher.processBlock(out, 16, out, 16);
  }
  return sha256(out);
}
