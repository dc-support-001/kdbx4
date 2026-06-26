import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/argon2.dart';

import '../test_util.dart';

void main() {
  // RFC 9106 test vectors. Common inputs:
  //   password = 32 x 0x01, salt = 16 x 0x02, secret = 8 x 0x03, ad = 12 x 0x04
  //   t = 3, m = 32 KiB, p = 4, version = 0x13, tag length = 32.
  final password = rep(0x01, 32);
  final salt = rep(0x02, 16);
  final secret = rep(0x03, 8);
  final ad = rep(0x04, 12);

  test('Argon2id KAT (RFC 9106)', () {
    final out = argon2(
      type: Argon2Type.id,
      password: password,
      salt: salt,
      secret: secret,
      additional: ad,
      memoryKiB: 32,
      iterations: 3,
      parallelism: 4,
    );
    expect(toHex(out),
        '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  test('Argon2d KAT (RFC 9106)', () {
    final out = argon2(
      type: Argon2Type.d,
      password: password,
      salt: salt,
      secret: secret,
      additional: ad,
      memoryKiB: 32,
      iterations: 3,
      parallelism: 4,
    );
    expect(toHex(out),
        '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb');
  });
}
