import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';

import '../format/kdbx_time.dart';
import '../kdbx_exceptions.dart';
import 'inner_random_stream.dart';
import 'kdbx_model.dart';

/// Parse KDBX inner XML into a [KdbxContent]. `Protected="True"` values are
/// decrypted with [unprotectStream] in document order; exported XML
/// (`ProtectInMemory="True"`, plaintext) needs no stream. Throws if protected
/// values are present without a stream.
KdbxContent readXml(String xml, InnerRandomStream? unprotectStream) {
  final doc = XmlDocument.parse(xml);

  final protectedValues = doc.descendants
      .whereType<XmlElement>()
      .where((e) =>
          e.name.local == 'Value' && e.getAttribute('Protected') == 'True')
      .toList();
  if (protectedValues.isNotEmpty) {
    if (unprotectStream == null) {
      throw KdbxFormatException(
          'protected values present but no inner stream provided');
    }
    for (final el in protectedValues) {
      final plain = unprotectStream.apply(base64.decode(el.innerText.trim()));
      el.children
        ..clear()
        ..add(XmlText(utf8.decode(plain)));
    }
  }

  final keePassFile = doc.rootElement;
  final metaEl = keePassFile.getElement('Meta');
  final meta = KdbxMeta(
    generator: metaEl?.getElement('Generator')?.innerText ?? '',
    databaseName: metaEl?.getElement('DatabaseName')?.innerText ?? '',
    customData: _customData(metaEl?.getElement('CustomData')),
  );
  final rootGroupEl = keePassFile.getElement('Root')?.getElement('Group');
  if (rootGroupEl == null) {
    throw KdbxFormatException('KDBX XML missing Root/Group');
  }
  return KdbxContent(meta: meta, root: _group(rootGroupEl));
}

KdbxGroup _group(XmlElement el) {
  final g = KdbxGroup(
    uuid: _uuid(el),
    name: el.getElement('Name')?.innerText ?? '',
    times: _times(el.getElement('Times')),
    customData: _customData(el.getElement('CustomData')),
  );
  for (final child in el.childElements) {
    switch (child.name.local) {
      case 'Entry':
        g.entries.add(_entry(child));
        break;
      case 'Group':
        g.groups.add(_group(child));
        break;
    }
  }
  return g;
}

KdbxEntry _entry(XmlElement el) {
  final e = KdbxEntry(
    uuid: _uuid(el),
    times: _times(el.getElement('Times')),
    customData: _customData(el.getElement('CustomData')),
  );
  final tags = el.getElement('Tags')?.innerText ?? '';
  if (tags.isNotEmpty) {
    e.tags.addAll(tags
        .split(RegExp(r'[;,]'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty));
  }
  for (final s in el.findElements('String')) {
    final key = s.getElement('Key')?.innerText ?? '';
    final valEl = s.getElement('Value');
    final protected = valEl?.getAttribute('Protected') == 'True' ||
        valEl?.getAttribute('ProtectInMemory') == 'True';
    e.strings[key] =
        KdbxStringValue(valEl?.innerText ?? '', protected: protected);
  }
  return e;
}

Uint8List _uuid(XmlElement el) {
  final t = el.getElement('UUID')?.innerText;
  if (t == null || t.trim().isEmpty) return Uint8List(16);
  return Uint8List.fromList(base64.decode(t.trim()));
}

KdbxTimes? _times(XmlElement? el) {
  if (el == null) return null;
  DateTime? p(String name) {
    final t = el.getElement(name)?.innerText;
    return (t == null || t.isEmpty) ? null : decodeKdbxTime(t);
  }

  return KdbxTimes(
    creation: p('CreationTime'),
    lastModification: p('LastModificationTime'),
    lastAccess: p('LastAccessTime'),
    expiry: p('ExpiryTime'),
    expires: el.getElement('Expires')?.innerText == 'True',
  );
}

Map<String, String> _customData(XmlElement? el) {
  final m = <String, String>{};
  if (el == null) return m;
  for (final item in el.findElements('Item')) {
    final k = item.getElement('Key')?.innerText;
    if (k != null) m[k] = item.getElement('Value')?.innerText ?? '';
  }
  return m;
}
