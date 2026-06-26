import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// SHA-256 of [data].
Uint8List sha256(List<int> data) =>
    SHA256Digest().process(Uint8List.fromList(data));

/// SHA-512 of [data].
Uint8List sha512(List<int> data) =>
    SHA512Digest().process(Uint8List.fromList(data));
