import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/aes_cbc.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  // NIST SP 800-38A F.2.5/F.2.6 — CBC-AES256.
  final key = hex('603deb1015ca71be2b73aef0857d7781'
      '1f352c073b6108d72d9810a30914dff4');
  final iv = hex('000102030405060708090a0b0c0d0e0f');
  final plain = hex('6bc1bee22e409f96e93d7e117393172a'
      'ae2d8a571e03ac9c9eb76fac45af8e51'
      '30c81c46a35ce411e5fbc1191a0a52ef'
      'f69f2445df4f9b17ad2b417be66c3710');
  final cipher = hex('f58c4c04d6e5f1ba779eabfb5f7bfbd6'
      '9cfc4e967edb808d679f777bc6702c7d'
      '39f23369a9d9bacfa530e26304231461'
      'b2eb05e2c39be9fcda6c19078c6a9d1b');

  test('AES-256-CBC encrypt KAT', () {
    expect(toHex(aesCbc(key, iv, plain, encrypt: true)), toHex(cipher));
  });

  test('AES-256-CBC decrypt KAT', () {
    expect(toHex(aesCbc(key, iv, cipher, encrypt: false)), toHex(plain));
  });

  test('non-block-aligned input throws', () {
    expect(
        () => aesCbc(key, iv, hex('0011'), encrypt: true), throwsArgumentError);
  });

  group('PKCS7', () {
    test('pad/unpad round-trip across all residues', () {
      for (var len = 0; len < 40; len++) {
        final data = rep(0xAB, len);
        final padded = pkcs7Pad(data);
        expect(padded.length % 16, 0);
        expect(padded.length, greaterThan(len)); // always adds 1..16
        expect(pkcs7Unpad(padded), data);
      }
    });

    test('bad padding throws', () {
      // 16 bytes ending in 0x05 but without 5 matching pad bytes.
      final bad = rep(0x00, 16)..[15] = 0x05;
      expect(() => pkcs7Unpad(bad), throwsA(isA<KdbxFormatException>()));
    });

    test('bad length throws', () {
      expect(
          () => pkcs7Unpad(rep(0x01, 17)), throwsA(isA<KdbxFormatException>()));
    });
  });
}
