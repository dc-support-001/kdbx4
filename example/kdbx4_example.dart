import 'package:kdbx4/kdbx4.dart';

/// Creates a KDBX4 vault in memory, writes it to bytes, and reopens it.
void main() {
  // Build a minimal vault: one group with one entry whose password is protected.
  final entry = KdbxEntry(uuid: secureRandomBytes(16), strings: {
    'Title': const KdbxStringValue('GitHub'),
    'UserName': const KdbxStringValue('octocat'),
    'Password': const KdbxStringValue('s3cr3t', protected: true),
  });
  final content = KdbxContent(
    meta: KdbxMeta(generator: 'kdbx4-example', databaseName: 'Demo'),
    root:
        KdbxGroup(uuid: secureRandomBytes(16), name: 'Root', entries: [entry]),
  );

  final creds = Credentials.password('correct horse battery staple');

  // Default KDF is Argon2id (64 MiB, t=3, p=1). serialize() -> Uint8List.
  final db = KdbxDatabase.create(
    content: content,
    kdf: Argon2Kdf.sesameDefault(secureRandomBytes(32)),
    credentials: creds,
  );
  final bytes = KdbxFile.serialize(db);
  print('wrote ${bytes.length} bytes');

  // Reopen with the same passcode (a wrong one throws WrongCredentialsException).
  final reopened = KdbxFile.open(
    bytes: bytes,
    credentials: Credentials.password('correct horse battery staple'),
  );
  final title = reopened.content.root.entries.single.strings['Title']!.value;
  print('reopened "${reopened.content.meta.databaseName}", entry: $title');
}
