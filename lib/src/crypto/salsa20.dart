import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Salsa20/20: 32-byte [key], 8-byte [iv]. Stream cipher (encrypt == decrypt).
///
/// Used only to read the legacy KDBX inner-random-stream (id 2), where KeePass
/// fixes the IV to `E8 30 09 4B 97 20 5D 2A` and keys it with
/// `SHA-256(streamKey)`. That wiring lives in the inner-stream layer (Phase 5);
/// this is the raw primitive.
Uint8List salsa20(Uint8List key, Uint8List iv, Uint8List input) {
  final engine = Salsa20Engine()
    ..init(true, ParametersWithIV(KeyParameter(key), iv));
  return engine.process(input);
}
