import 'package:test/test.dart';
import 'package:kdbx4/src/keys/credentials.dart';

import '../test_util.dart';

void main() {
  // Expected values precomputed with Python hashlib (SHA-256(SHA-256(pw))).
  test('password-only composite key KAT', () {
    final c = Credentials.password('TestPass123!');
    expect(toHex(c.compositeKey()),
        'a6ffde15dc7078eb40b4873b6509709b3a1a5068505c4dec374bc84e15843a6b');
  });

  test('password + keyfile component KAT', () {
    final c = Credentials.password('TestPass123!')
      ..addKeyComponent(rep(0xAB, 32));
    expect(toHex(c.compositeKey()),
        '5253a8c986f342d2589d6c47863062824e6a7803813144b620dfc4e5288c160e');
  });

  test('rejects non-32-byte component', () {
    expect(() => Credentials.password('x').addKeyComponent(rep(0, 16)),
        throwsArgumentError);
  });
}
