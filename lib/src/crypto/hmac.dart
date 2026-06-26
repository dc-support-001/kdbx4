import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// HMAC-SHA-256 of [data] under [key]. (SHA-256 block size is 64 bytes.)
Uint8List hmacSha256(Uint8List key, Uint8List data) {
  final h = HMac(SHA256Digest(), 64)..init(KeyParameter(key));
  return h.process(data);
}
