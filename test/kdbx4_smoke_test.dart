import 'dart:typed_data';

import 'package:test/test.dart';
// Import ONLY the public barrel — this also asserts the public API surface is
// sufficient to create, write, and reopen a vault end-to-end.
import 'package:kdbx4/kdbx4.dart';

void main() {
  test('public API: create → serialize → open round-trips an entry', () {
    final entry = KdbxEntry(uuid: secureRandomBytes(16), strings: {
      'Title': const KdbxStringValue('GitHub'),
      'Password': const KdbxStringValue('s3cr3t', protected: true),
    });
    final content = KdbxContent(
      meta: KdbxMeta(databaseName: 'Smoke'),
      root: KdbxGroup(
          uuid: secureRandomBytes(16), name: 'Root', entries: [entry]),
    );
    final creds = Credentials.password('pw');

    // Fast KDF (AES rounds) so the smoke test stays quick.
    final db = KdbxDatabase.create(
      content: content,
      kdf: AesKdf(seed: Uint8List(32), rounds: 1000),
      credentials: creds,
    );
    final bytes = KdbxFile.serialize(db);
    expect(bytes, isNotEmpty);

    final reopened =
        KdbxFile.open(bytes: bytes, credentials: Credentials.password('pw'));
    expect(reopened.content.meta.databaseName, 'Smoke');
    final e = reopened.content.root.entries.single;
    expect(e.strings['Title']!.value, 'GitHub');
    expect(e.strings['Password']!.value, 's3cr3t');
  });

  test('wrong passcode throws WrongCredentialsException', () {
    final content = KdbxContent(
      meta: KdbxMeta(databaseName: 'X'),
      root: KdbxGroup(uuid: secureRandomBytes(16), name: 'Root'),
    );
    final bytes = KdbxFile.serialize(KdbxDatabase.create(
      content: content,
      kdf: AesKdf(seed: Uint8List(32), rounds: 1000),
      credentials: Credentials.password('right'),
    ));
    expect(
      () => KdbxFile.open(
          bytes: bytes, credentials: Credentials.password('wrong')),
      throwsA(isA<WrongCredentialsException>()),
    );
  });
}
