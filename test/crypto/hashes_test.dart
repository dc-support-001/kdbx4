import 'dart:convert';

import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/hashes.dart';

import '../test_util.dart';

void main() {
  group('SHA-256 KAT', () {
    test('empty', () {
      expect(toHex(sha256(const [])),
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
    test('"abc"', () {
      expect(toHex(sha256(utf8.encode('abc'))),
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });
  });

  group('SHA-512 KAT', () {
    test('empty', () {
      expect(
          toHex(sha512(const [])),
          'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
          '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
    });
    test('"abc"', () {
      expect(
          toHex(sha512(utf8.encode('abc'))),
          'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
          '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
    });
  });
}
