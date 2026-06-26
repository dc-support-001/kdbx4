import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/salsa20.dart';

import '../test_util.dart';

void main() {
  // eSTREAM Salsa20/20 256-bit, Set 1, vector #0:
  // key = 0x80 followed by zeros, IV = 0. Keystream bytes [0..63].
  test('Salsa20/20 keystream KAT (eSTREAM Set 1 #0)', () {
    final key = rep(0x00, 32)..[0] = 0x80;
    final iv = rep(0x00, 8);
    final out = salsa20(key, iv, rep(0x00, 64));
    expect(
        toHex(out).toUpperCase(),
        'E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844'
        'B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117');
  });
}
