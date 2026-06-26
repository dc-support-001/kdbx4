import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/hmac.dart';

import '../test_util.dart';

void main() {
  // RFC 4231 Test Case 2.
  test('HMAC-SHA-256 KAT (RFC 4231 #2)', () {
    final key = Uint8List.fromList(utf8.encode('Jefe'));
    final data =
        Uint8List.fromList(utf8.encode('what do ya want for nothing?'));
    expect(toHex(hmacSha256(key, data)),
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });
}
