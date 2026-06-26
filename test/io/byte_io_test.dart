import 'package:test/test.dart';
import 'package:kdbx4/src/io/byte_reader.dart';
import 'package:kdbx4/src/io/byte_writer.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

void main() {
  group('ByteWriter/ByteReader round-trip', () {
    test('u8/u16/u32/u64 with boundary values', () {
      final w = ByteWriter()
        ..u8(0)
        ..u8(0xff)
        ..u16(0)
        ..u16(0xffff)
        ..u32(0)
        ..u32(0xffffffff)
        ..u64(0)
        ..u64(0x0102030405060708);
      final r = ByteReader(w.toBytes());
      expect(r.u8(), 0);
      expect(r.u8(), 0xff);
      expect(r.u16(), 0);
      expect(r.u16(), 0xffff);
      expect(r.u32(), 0);
      expect(r.u32(), 0xffffffff);
      expect(r.u64(), 0);
      expect(r.u64(), 0x0102030405060708);
      expect(r.hasMore, isFalse);
      expect(r.remaining, 0);
    });

    test('little-endian byte order is correct', () {
      final w = ByteWriter()..u32(0x01020304);
      // 0x01020304 little-endian => 04 03 02 01
      expect(w.toBytes(), [0x04, 0x03, 0x02, 0x01]);
    });

    test('bytes + take views', () {
      final w = ByteWriter()..bytes([1, 2, 3, 4, 5]);
      final r = ByteReader(w.toBytes());
      expect(r.take(2), [1, 2]);
      expect(r.position, 2);
      expect(r.takeRemaining(), [3, 4, 5]);
      expect(r.hasMore, isFalse);
    });
  });

  group('ByteReader bounds', () {
    test('reading past end throws KdbxFormatException', () {
      final r = ByteReader.fromList([0x01, 0x02]);
      r.u8();
      expect(() => r.u32(), throwsA(isA<KdbxFormatException>()));
    });

    test('take past end throws', () {
      final r = ByteReader.fromList([1, 2, 3]);
      expect(() => r.take(4), throwsA(isA<KdbxFormatException>()));
    });
  });
}
