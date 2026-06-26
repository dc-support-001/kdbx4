import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:kdbx4/src/content/inner_random_stream.dart';
import 'package:kdbx4/src/crypto/chacha20.dart';
import 'package:kdbx4/src/crypto/hashes.dart';
import 'package:kdbx4/src/crypto/salsa20.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  final streamKey = rep(0x5A, 64);

  test('ChaCha20 wiring matches SHA512-split keying', () {
    final s = InnerRandomStream.create(innerStreamChaCha20, streamKey);
    final h = sha512(streamKey);
    final expected = chacha20(Uint8List.sublistView(h, 0, 32),
        Uint8List.sublistView(h, 32, 44), rep(0x00, 64));
    expect(toHex(s.apply(rep(0x00, 64))), toHex(expected));
  });

  test('Salsa20 wiring matches SHA256 key + fixed IV', () {
    final s = InnerRandomStream.create(innerStreamSalsa20, streamKey);
    final fixedIv =
        Uint8List.fromList([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);
    final expected = salsa20(sha256(streamKey), fixedIv, rep(0x00, 64));
    expect(toHex(s.apply(rep(0x00, 64))), toHex(expected));
  });

  test('protect then unprotect recovers values in document order', () {
    for (final id in [innerStreamChaCha20, innerStreamSalsa20]) {
      final protect = InnerRandomStream.create(id, streamKey);
      final unprotect = InnerRandomStream.create(id, streamKey);
      final values = [
        hex('001122'),
        hex('aabbccddeeff'),
        hex('5566778899'),
      ];
      final cts = values.map(protect.apply).toList();
      // Different from plaintext (it actually encrypted something).
      expect(toHex(cts[0]), isNot(toHex(values[0])));
      // Unprotect in the same order recovers each value.
      for (var i = 0; i < values.length; i++) {
        expect(toHex(unprotect.apply(cts[i])), toHex(values[i]));
      }
    }
  });

  test('unknown stream id throws', () {
    expect(() => InnerRandomStream.create(99, streamKey),
        throwsA(isA<KdbxFormatException>()));
  });
}
