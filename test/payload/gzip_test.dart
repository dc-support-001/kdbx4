import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:kdbx4/src/payload/gzip.dart';

import '../test_util.dart';

void main() {
  test('round-trips arbitrary data', () {
    final data = hex('00112233445566778899aabbccddeeff');
    expect(toHex(gzipDecompress(gzipCompress(data))), toHex(data));
  });

  test('round-trips empty', () {
    expect(gzipDecompress(gzipCompress(Uint8List(0))), isEmpty);
  });

  test('round-trips large, compressible payload', () {
    final data = Uint8List(2 * 1024 * 1024);
    for (var i = 0; i < data.length; i++) {
      data[i] = i & 0xff;
    }
    final compressed = gzipCompress(data);
    expect(compressed.length, lessThan(data.length)); // actually compresses
    expect(gzipDecompress(compressed), data);
  });
}
