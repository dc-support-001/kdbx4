import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';
import 'package:kdbx4/src/payload/hmac_block_stream.dart';

import '../test_util.dart';

void main() {
  final hmacBase = rep(0x33, 64);

  test('round-trips a small payload', () {
    final data = hex('00112233445566778899aabbccddeeff');
    final framed = HmacBlockStream.write(data, hmacBase);
    expect(toHex(HmacBlockStream.read(framed, hmacBase)), toHex(data));
  });

  test('round-trips empty payload (terminator only)', () {
    final framed = HmacBlockStream.write(Uint8List(0), hmacBase);
    expect(HmacBlockStream.read(framed, hmacBase), isEmpty);
  });

  test('round-trips across the 1 MiB block boundary', () {
    final data = Uint8List(HmacBlockStream.blockSize + 100);
    for (var i = 0; i < data.length; i++) {
      data[i] = (i * 31) & 0xff;
    }
    final framed = HmacBlockStream.write(data, hmacBase);
    expect(HmacBlockStream.read(framed, hmacBase), data);
  });

  group('tamper detection', () {
    final data = hex('aabbccddeeff00112233445566778899');

    test('flipped data byte rejected', () {
      final framed = HmacBlockStream.write(data, hmacBase);
      // Byte layout: [hmac(32)][len(4)][data...]; flip first data byte.
      framed[36] ^= 0x01;
      expect(() => HmacBlockStream.read(framed, hmacBase),
          throwsA(isA<KdbxIntegrityException>()));
    });

    test('flipped HMAC byte rejected', () {
      final framed = HmacBlockStream.write(data, hmacBase);
      framed[0] ^= 0x80;
      expect(() => HmacBlockStream.read(framed, hmacBase),
          throwsA(isA<KdbxIntegrityException>()));
    });

    test('wrong hmacBase rejected', () {
      final framed = HmacBlockStream.write(data, hmacBase);
      expect(() => HmacBlockStream.read(framed, rep(0x44, 64)),
          throwsA(isA<KdbxIntegrityException>()));
    });

    test('truncated stream rejected', () {
      final framed = HmacBlockStream.write(data, hmacBase);
      final cut = Uint8List.sublistView(framed, 0, framed.length - 5);
      expect(() => HmacBlockStream.read(cut, hmacBase),
          throwsA(isA<KdbxFormatException>()));
    });
  });
}
