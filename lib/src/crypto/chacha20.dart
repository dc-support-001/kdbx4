import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// IETF ChaCha20 (RFC 7539/8439): 32-byte [key], 12-byte [nonce], 32-bit block
/// counter starting at 0. Stream cipher, so the same call both encrypts and
/// decrypts. Used as the KDBX4 inner-stream protector and as an optional outer
/// cipher.
Uint8List chacha20(Uint8List key, Uint8List nonce, Uint8List input) {
  final engine = ChaCha7539Engine()
    ..init(true, ParametersWithIV(KeyParameter(key), nonce));
  return engine.process(input);
}
