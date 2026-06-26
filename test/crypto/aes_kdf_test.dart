import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/aes_kdf.dart';
import 'package:kdbx4/src/crypto/hashes.dart';

import '../test_util.dart';

void main() {
  // Pin the AES-256-ECB core with NIST SP 800-38A F.1.5/F.1.6 vectors, then
  // assert the KDF composes them as SHA-256(ECB(half0) || ECB(half1)).
  final seed = hex('603deb1015ca71be2b73aef0857d7781'
      '1f352c073b6108d72d9810a30914dff4'); // ECB key
  final pt0 = hex('6bc1bee22e409f96e93d7e117393172a');
  final pt1 = hex('ae2d8a571e03ac9c9eb76fac45af8e51');
  final ct0 = hex('f3eed1bdb5d2a03c064b5a7e3db181f8');
  final ct1 = hex('591ccb10d410ed26dc5ba74a31362870');

  test('AES-KDF rounds=1 KAT (NIST ECB vectors)', () {
    final key32 = hex(toHex(pt0) + toHex(pt1));
    final expected = sha256(hex(toHex(ct0) + toHex(ct1)));
    expect(toHex(aesKdfTransform(key32, seed, 1)), toHex(expected));
  });

  test('AES-KDF rounds=0 is SHA-256(key)', () {
    final key32 = rep(0x11, 32);
    expect(toHex(aesKdfTransform(key32, seed, 0)), toHex(sha256(key32)));
  });

  test('AES-KDF is deterministic and rounds-sensitive', () {
    final key32 = rep(0x22, 32);
    expect(toHex(aesKdfTransform(key32, seed, 2)),
        toHex(aesKdfTransform(key32, seed, 2)));
    expect(toHex(aesKdfTransform(key32, seed, 2)),
        isNot(toHex(aesKdfTransform(key32, seed, 3))));
  });
}
