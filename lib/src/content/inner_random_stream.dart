import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../crypto/hashes.dart';
import '../kdbx_exceptions.dart';

const int innerStreamSalsa20 = 2;
const int innerStreamChaCha20 = 3;

/// KeePass's fixed Salsa20 IV for the inner random stream.
final Uint8List _salsaFixedIv =
    Uint8List.fromList([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);

/// The KDBX inner random stream that protects in-memory fields (Password).
///
/// It is a keystream the whole document shares: protected values are XOR'd
/// against it **in document order**. Encrypt and decrypt are the same XOR, so
/// the writer and reader each create one stream from the same key and consume
/// it in the same order. Keying:
/// - **ChaCha20** (id 3): `key = SHA512(streamKey)[0..32]`, `nonce = [32..44]`.
/// - **Salsa20** (id 2): `key = SHA256(streamKey)`, fixed IV.
abstract class InnerRandomStream {
  /// XOR [data] with the next keystream bytes (stateful; advances the stream).
  Uint8List apply(Uint8List data);

  factory InnerRandomStream.create(int streamId, Uint8List streamKey) {
    switch (streamId) {
      case innerStreamChaCha20:
        final h = sha512(streamKey);
        return _EngineStream(ChaCha7539Engine()
          ..init(
              true,
              ParametersWithIV(
                KeyParameter(Uint8List.sublistView(h, 0, 32)),
                Uint8List.sublistView(h, 32, 44),
              )));
      case innerStreamSalsa20:
        return _EngineStream(Salsa20Engine()
          ..init(
              true,
              ParametersWithIV(
                  KeyParameter(sha256(streamKey)), _salsaFixedIv)));
      default:
        throw KdbxFormatException(
            'unsupported inner random stream id $streamId');
    }
  }
}

class _EngineStream implements InnerRandomStream {
  final StreamCipher _engine;
  _EngineStream(this._engine);

  @override
  Uint8List apply(Uint8List data) => _engine.process(data);
}
