import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/chacha20.dart';

import '../test_util.dart';

void main() {
  // RFC 8439 Appendix A.1 Test Vector #1: zero key, zero nonce, block counter 0.
  // XORing the all-zero plaintext yields the keystream itself.
  test('ChaCha20 keystream KAT (RFC 8439 A.1 #1)', () {
    final key = rep(0x00, 32);
    final nonce = rep(0x00, 12);
    final out = chacha20(key, nonce, rep(0x00, 64));
    expect(
        toHex(out),
        '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'
        'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586');
  });

  test('encrypt then decrypt round-trips', () {
    final key = rep(0x42, 32);
    final nonce = rep(0x07, 12);
    final msg = hex('00112233445566778899aabbccddeeff1020');
    final ct = chacha20(key, nonce, msg);
    expect(toHex(ct), isNot(toHex(msg)));
    expect(toHex(chacha20(key, nonce, ct)), toHex(msg));
  });
}
