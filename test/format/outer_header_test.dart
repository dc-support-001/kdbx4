import 'dart:io';

import 'package:test/test.dart';
import 'package:kdbx4/src/format/outer_header.dart';
import 'package:kdbx4/src/format/var_dictionary.dart';
import 'package:kdbx4/src/io/byte_reader.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

// Well-known KDBX UUIDs.
final aes256Cipher = hex('31c1f2e6bf714350be5805216afc5aff');
final aesKdfUuid = hex('c9d9f39a628a4460bf740d08c18a4fea');
final argon2dUuid = hex('ef636ddf8c29444b91f7a9a403e30a0c');

void main() {
  group('OuterHeader round-trip', () {
    test('serialize → parse preserves fields and captures rawBytes', () {
      final kdf = VarDictionary()
        ..setBytes(r'$UUID', argon2dUuid)
        ..setBytes('S', rep(0xAB, 32))
        ..setUint32('P', 1)
        ..setUint64('M', 64 * 1024 * 1024)
        ..setUint64('I', 3)
        ..setUint32('V', 0x13);
      final header = OuterHeader(
        cipherId: aes256Cipher,
        compression: 1,
        masterSeed: rep(0x11, 32),
        encryptionIV: rep(0x22, 16),
        kdfParameters: kdf,
      );

      final bytes = header.serialize();
      final parsed = OuterHeader.parse(ByteReader(bytes));

      expect(parsed.versionMajor, 4);
      expect(parsed.versionMinor, 0);
      expect(toHex(parsed.cipherId), toHex(aes256Cipher));
      expect(parsed.compression, 1);
      expect(toHex(parsed.masterSeed), toHex(rep(0x11, 32)));
      expect(toHex(parsed.encryptionIV), toHex(rep(0x22, 16)));
      expect(
          toHex(parsed.kdfParameters.getBytes(r'$UUID')!), toHex(argon2dUuid));
      expect(parsed.kdfParameters.getUint64('M'), 64 * 1024 * 1024);
      // rawBytes is exactly the serialized header (whole input here).
      expect(toHex(parsed.rawBytes!), toHex(bytes));
    });

    test('bad signature throws', () {
      expect(() => OuterHeader.parse(ByteReader.fromList(List.filled(20, 0))),
          throwsA(isA<KdbxFormatException>()));
    });
  });

  group('OuterHeader FIX (real KeePassXC files)', () {
    test('KDBX 3.1 file (AES-KDF) is rejected — we support KDBX4 only', () {
      // KeePassXC CLI `db-create` defaults to AES-KDF, which is a KDBX 3.1
      // file. KDBX3 has a different header/body format; out of scope (§13:
      // read 4.0/4.1). Assert a clean version rejection, not a crash.
      final bytes =
          File('test/fixtures/kpxc_kdbx3_aeskdf.kdbx').readAsBytesSync();
      expect(() => OuterHeader.parse(ByteReader(bytes)),
          throwsA(isA<KdbxFormatException>()));
    });

    test('AES-KDF params inside a KDBX4 header round-trip', () {
      // A KDBX4 file *may* use AES-KDF (UUID + R rounds + S seed). We don't
      // have a foreign KDBX4+AES-KDF file, so verify the header/VarDictionary
      // path with a synthetic one.
      final kdf = VarDictionary()
        ..setBytes(r'$UUID', aesKdfUuid)
        ..setUint64('R', 60000)
        ..setBytes('S', rep(0xC3, 32));
      final header = OuterHeader(
        cipherId: aes256Cipher,
        compression: 1,
        masterSeed: rep(0x11, 32),
        encryptionIV: rep(0x22, 16),
        kdfParameters: kdf,
      );
      final parsed = OuterHeader.parse(ByteReader(header.serialize()));
      expect(
          toHex(parsed.kdfParameters.getBytes(r'$UUID')!), toHex(aesKdfUuid));
      expect(parsed.kdfParameters.getUint64('R'), 60000);
      expect(parsed.kdfParameters.getBytes('S')!.length, 32);
    });

    test('Argon2d vault', () {
      final bytes = File('test/fixtures/kpxc_argon2.kdbx').readAsBytesSync();
      final h = OuterHeader.parse(ByteReader(bytes));

      expect(h.versionMajor, 4);
      expect(toHex(h.cipherId), toHex(aes256Cipher));
      expect(toHex(h.kdfParameters.getBytes(r'$UUID')!), toHex(argon2dUuid));
      expect(h.kdfParameters.getBytes('S')!.length, 32);
      expect(h.kdfParameters.getUint32('P'), isNotNull);
      expect(h.kdfParameters.getUint64('M'), isNotNull); // memory in bytes
      expect(h.kdfParameters.getUint64('I'), isNotNull); // iterations
      expect(h.kdfParameters.getUint32('V'), 0x13); // Argon2 v1.3
    });
  });
}
