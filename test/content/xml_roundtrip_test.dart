import 'dart:io';

import 'package:test/test.dart';
import 'package:kdbx4/src/content/inner_random_stream.dart';
import 'package:kdbx4/src/content/kdbx_model.dart';
import 'package:kdbx4/src/content/xml_reader.dart';
import 'package:kdbx4/src/content/xml_writer.dart';

import '../test_util.dart';

KdbxEntry _entry(String title, String user, String pass, String eid) =>
    KdbxEntry(
      uuid: rep(title.codeUnitAt(0), 16),
      times: KdbxTimes(
        creation: DateTime.utc(2026, 6, 2, 10, 0, 0),
        lastModification: DateTime.utc(2026, 6, 2, 11, 30, 0),
      ),
      strings: {
        'Title': KdbxStringValue(title),
        'UserName': KdbxStringValue(user),
        'Password': KdbxStringValue(pass, protected: true),
      },
      customData: {'sesame_eid': eid},
    );

void main() {
  final streamKey = rep(0x77, 64);

  KdbxContent sample() => KdbxContent(
        meta: KdbxMeta(generator: 'Sesame PS', databaseName: 'Vault'),
        root: KdbxGroup(uuid: rep(0x01, 16), name: 'Root', groups: [
          KdbxGroup(uuid: rep(0x02, 16), name: 'Current', entries: [
            _entry('Gmail', 'jeff@example.com', 's3cr3t-P@ss!', 'eid-1'),
            _entry('Bank', 'jeff', 'h2#vault\$Pw', 'eid-2'),
          ]),
        ]),
      );

  test('write → read round-trips structure, protected values, customData', () {
    final xml = writeXml(
        sample(), InnerRandomStream.create(innerStreamChaCha20, streamKey));

    // Passwords must not appear in plaintext in the serialized XML.
    expect(xml.contains('s3cr3t-P@ss!'), isFalse);
    expect(xml.contains('Protected="True"'), isTrue);

    final content =
        readXml(xml, InnerRandomStream.create(innerStreamChaCha20, streamKey));

    expect(content.meta.databaseName, 'Vault');
    final current = content.root.groups.single;
    expect(current.name, 'Current');
    expect(current.entries.length, 2);

    final gmail = current.entries[0];
    expect(gmail.strings['Title']!.value, 'Gmail');
    expect(gmail.strings['UserName']!.value, 'jeff@example.com');
    expect(gmail.strings['Password']!.value, 's3cr3t-P@ss!');
    expect(gmail.strings['Password']!.protected, isTrue);
    expect(gmail.customData['sesame_eid'], 'eid-1');
    expect(gmail.times!.lastModification, DateTime.utc(2026, 6, 2, 11, 30, 0));

    // Second entry's protected value also recovered (document-order stream).
    expect(current.entries[1].strings['Password']!.value, 'h2#vault\$Pw');
    expect(current.entries[1].customData['sesame_eid'], 'eid-2');
  });

  test('protected values present without a stream throws', () {
    final xml = writeXml(
        sample(), InnerRandomStream.create(innerStreamChaCha20, streamKey));
    expect(() => readXml(xml, null), throwsA(anything));
  });

  test('FIX: parses a real KeePassXC XML export', () {
    final xml = File('test/fixtures/kpxc_export.xml').readAsStringSync();
    // Export has no Protected="True" (uses ProtectInMemory + plaintext).
    final content = readXml(xml, null);

    final entries = <KdbxEntry>[];
    void collect(KdbxGroup g) {
      entries.addAll(g.entries);
      g.groups.forEach(collect);
    }

    collect(content.root);
    final gmail =
        entries.firstWhere((e) => e.strings['Title']?.value == 'Gmail');
    expect(gmail.strings['UserName']!.value, 'jeff@example.com');
    expect(gmail.strings['Password']!.value, 's3cr3t-P@ss!');
    expect(gmail.strings['Password']!.protected, isTrue); // ProtectInMemory
  });
}
