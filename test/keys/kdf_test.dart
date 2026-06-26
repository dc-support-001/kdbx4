import 'package:test/test.dart';
import 'package:kdbx4/src/crypto/argon2.dart';
import 'package:kdbx4/src/crypto/hashes.dart';
import 'package:kdbx4/src/format/var_dictionary.dart';
import 'package:kdbx4/src/keys/kdf.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  group('Kdf.fromVarDict → transform KAT', () {
    test('Argon2id reproduces RFC 9106 vector through dispatch', () {
      // RFC 9106 inputs encoded as KDBX KDF params (incl. optional K/A).
      final vd = VarDictionary()
        ..setBytes(r'$UUID', kdfArgon2id)
        ..setBytes('S', rep(0x02, 16))
        ..setUint32('P', 4)
        ..setUint64('M', 32 * 1024) // 32 KiB in bytes
        ..setUint64('I', 3)
        ..setUint32('V', 0x13)
        ..setBytes('K', rep(0x03, 8))
        ..setBytes('A', rep(0x04, 12));
      final kdf = Kdf.fromVarDict(vd);
      expect(kdf, isA<Argon2Kdf>());
      expect(toHex(kdf.transform(rep(0x01, 32))),
          '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    });

    test('AES-KDF dispatch transforms via NIST-pinned core', () {
      final seed = hex('603deb1015ca71be2b73aef0857d7781'
          '1f352c073b6108d72d9810a30914dff4');
      final composite = hex('6bc1bee22e409f96e93d7e117393172a'
          'ae2d8a571e03ac9c9eb76fac45af8e51');
      final vd = VarDictionary()
        ..setBytes(r'$UUID', kdfAes)
        ..setUint64('R', 1)
        ..setBytes('S', seed);
      final kdf = Kdf.fromVarDict(vd);
      expect(kdf, isA<AesKdf>());
      // rounds=1 over the two NIST plaintext blocks → SHA-256 of the two
      // NIST ciphertext blocks (see aes_kdf_test).
      expect(
          toHex(kdf.transform(composite)),
          toHex(sha256(hex('f3eed1bdb5d2a03c064b5a7e3db181f8'
              '591ccb10d410ed26dc5ba74a31362870'))));
    });

    test('unknown KDF UUID throws', () {
      final vd = VarDictionary()..setBytes(r'$UUID', rep(0x00, 16));
      expect(
          () => Kdf.fromVarDict(vd), throwsA(isA<UnsupportedKdfException>()));
    });
  });

  group('Kdf toVarDict round-trip', () {
    test('Argon2id default config', () {
      final kdf = Argon2Kdf.sesameDefault(rep(0x09, 32));
      final back = Kdf.fromVarDict(kdf.toVarDict()) as Argon2Kdf;
      expect(back.type, Argon2Type.id);
      expect(back.memoryKiB, 64 * 1024);
      expect(back.iterations, 3);
      expect(back.parallelism, 1);
      expect(back.version, 0x13);
      expect(toHex(back.salt), toHex(rep(0x09, 32)));
    });

    test('AES-KDF', () {
      final kdf = AesKdf(seed: rep(0x07, 32), rounds: 60000);
      final back = Kdf.fromVarDict(kdf.toVarDict()) as AesKdf;
      expect(back.rounds, 60000);
      expect(toHex(back.seed), toHex(rep(0x07, 32)));
    });
  });
}
