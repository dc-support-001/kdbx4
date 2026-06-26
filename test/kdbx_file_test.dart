import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:kdbx4/src/content/inner_random_stream.dart';
import 'package:kdbx4/src/content/kdbx_model.dart';
import 'package:kdbx4/src/crypto/argon2.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';
import 'package:kdbx4/src/kdbx_file.dart';
import 'package:kdbx4/src/keys/credentials.dart';
import 'package:kdbx4/src/keys/kdf.dart';
import 'package:kdbx4/src/payload/cipher.dart';

import 'test_util.dart';

// Fast KDFs for tests (real default is Argon2id 64 MiB / t=3).
Kdf _tinyArgon2id() => Argon2Kdf(
    type: Argon2Type.id,
    salt: rep(0x01, 32),
    memoryKiB: 512,
    iterations: 1,
    parallelism: 1);
Kdf _fastAesKdf() => AesKdf(seed: rep(0x02, 32), rounds: 1000);

KdbxContent _sample() => KdbxContent(
      meta: KdbxMeta(generator: 'Sesame PS', databaseName: 'Vault'),
      root: KdbxGroup(uuid: rep(0x01, 16), name: 'Root', groups: [
        KdbxGroup(uuid: rep(0x02, 16), name: 'Current', entries: [
          KdbxEntry(uuid: rep(0xA1, 16), strings: {
            'Title': const KdbxStringValue('Gmail'),
            'UserName': const KdbxStringValue('jeff@example.com'),
            'Password': const KdbxStringValue('s3cr3t-P@ss!', protected: true),
          }, customData: {
            'sesame_eid': 'eid-1'
          }),
          KdbxEntry(uuid: rep(0xA2, 16), strings: {
            'Title': const KdbxStringValue('Bank'),
            'Password': const KdbxStringValue('h2#vault\$Pw', protected: true),
          }),
        ]),
      ]),
    );

void _assertSample(KdbxContent c) {
  final current = c.root.groups.single;
  expect(current.name, 'Current');
  final gmail = current.entries[0];
  expect(gmail.strings['Title']!.value, 'Gmail');
  expect(gmail.strings['UserName']!.value, 'jeff@example.com');
  expect(gmail.strings['Password']!.value, 's3cr3t-P@ss!');
  expect(gmail.strings['Password']!.protected, isTrue);
  expect(gmail.customData['sesame_eid'], 'eid-1');
  expect(current.entries[1].strings['Password']!.value, 'h2#vault\$Pw');
}

void main() {
  test('write → read round-trip (Argon2id, AES-256, gzip)', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('hunter2'),
        kdf: _tinyArgon2id());
    final back = KdbxFile.read(
        bytes: bytes, credentials: Credentials.password('hunter2'));
    _assertSample(back);
  });

  test('round-trip with AES-KDF', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('pw'),
        kdf: _fastAesKdf());
    _assertSample(
        KdbxFile.read(bytes: bytes, credentials: Credentials.password('pw')));
  });

  test('round-trip with ChaCha20 outer cipher and no compression', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('pw'),
        kdf: _fastAesKdf(),
        cipherId: cipherChaCha20,
        compression: compressionNone);
    _assertSample(
        KdbxFile.read(bytes: bytes, credentials: Credentials.password('pw')));
  });

  test('round-trip with Salsa20 inner stream', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('pw'),
        kdf: _fastAesKdf(),
        innerStreamId: innerStreamSalsa20);
    _assertSample(
        KdbxFile.read(bytes: bytes, credentials: Credentials.password('pw')));
  });

  test('wrong password throws WrongCredentialsException', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('right'),
        kdf: _fastAesKdf());
    expect(
        () => KdbxFile.read(
            bytes: bytes, credentials: Credentials.password('wrong')),
        throwsA(isA<WrongCredentialsException>()));
  });

  test('corrupt body throws KdbxIntegrityException', () {
    final bytes = KdbxFile.write(
        content: _sample(),
        credentials: Credentials.password('pw'),
        kdf: _fastAesKdf());
    final tampered = Uint8List.fromList(bytes);
    tampered[tampered.length - 40] ^= 0x01; // inside the block stream
    expect(
        () => KdbxFile.read(
            bytes: tampered, credentials: Credentials.password('pw')),
        throwsA(isA<KdbxIntegrityException>()));
  });
}
