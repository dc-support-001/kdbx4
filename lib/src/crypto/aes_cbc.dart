import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../kdbx_exceptions.dart';

const int _blockSize = 16;

/// AES-256-CBC over block-aligned [input]. [encrypt] selects direction.
///
/// Padding is the caller's concern ([pkcs7Pad] / [pkcs7Unpad]) so this stays a
/// pure block transform.
Uint8List aesCbc(Uint8List key, Uint8List iv, Uint8List input,
    {required bool encrypt}) {
  if (input.length % _blockSize != 0) {
    throw ArgumentError('AES-CBC input not block-aligned (${input.length})');
  }
  final cipher = CBCBlockCipher(AESEngine())
    ..init(encrypt, ParametersWithIV(KeyParameter(key), iv));
  final out = Uint8List(input.length);
  var off = 0;
  while (off < input.length) {
    off += cipher.processBlock(input, off, out, off);
  }
  return out;
}

/// PKCS#7 pad to the AES block size. Always adds 1..16 bytes.
Uint8List pkcs7Pad(Uint8List data) {
  final pad = _blockSize - (data.length % _blockSize);
  final out = Uint8List(data.length + pad)..setAll(0, data);
  for (var i = data.length; i < out.length; i++) {
    out[i] = pad;
  }
  return out;
}

/// Remove and validate PKCS#7 padding. Throws [KdbxFormatException] if invalid.
Uint8List pkcs7Unpad(Uint8List data) {
  if (data.isEmpty || data.length % _blockSize != 0) {
    throw KdbxFormatException('bad PKCS7 length ${data.length}');
  }
  final pad = data[data.length - 1];
  if (pad < 1 || pad > _blockSize) {
    throw KdbxFormatException('bad PKCS7 pad byte $pad');
  }
  for (var i = data.length - pad; i < data.length; i++) {
    if (data[i] != pad) throw KdbxFormatException('bad PKCS7 padding');
  }
  return Uint8List.sublistView(data, 0, data.length - pad);
}
