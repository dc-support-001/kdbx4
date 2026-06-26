import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/aes_cbc.dart';
import 'package:kdbx4/src/crypto/chacha20.dart';
import 'package:kdbx4/src/payload/cipher.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  final key = rep(0x2b, 32);

  group('AES-256 outer cipher', () {
    final iv = rep(0x10, 16);

    test('encrypt → decrypt round-trips (with PKCS7)', () {
      final plain = hex('deadbeefcafe'); // not block-aligned
      final ct = OuterCipher.encrypt(cipherAes256, key, iv, plain);
      expect(ct.length % 16, 0);
      expect(
          toHex(OuterCipher.decrypt(cipherAes256, key, iv, ct)), toHex(plain));
    });

    test('decrypt cross-checks the Phase-1 primitive', () {
      final plain = hex('00112233445566778899aabbccddeeff0a0b');
      final ct = aesCbc(key, iv, pkcs7Pad(plain), encrypt: true);
      expect(
          toHex(OuterCipher.decrypt(cipherAes256, key, iv, ct)), toHex(plain));
    });
  });

  group('ChaCha20 outer cipher', () {
    final nonce = rep(0x07, 12);

    test('matches the Phase-1 primitive and round-trips', () {
      final plain = hex('001122334455667788990a0b0c0d');
      final ct = OuterCipher.encrypt(cipherChaCha20, key, nonce, plain);
      expect(toHex(ct), toHex(chacha20(key, nonce, plain)));
      expect(toHex(OuterCipher.decrypt(cipherChaCha20, key, nonce, ct)),
          toHex(plain));
    });
  });

  test('unknown cipher UUID throws', () {
    expect(
        () => OuterCipher.decrypt(rep(0x00, 16), key, rep(0, 16), rep(0, 16)),
        throwsA(isA<UnsupportedCipherException>()));
  });
}
