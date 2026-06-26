import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';

import '../format/kdbx_time.dart';
import 'inner_random_stream.dart';
import 'kdbx_model.dart';

/// Serialize a [KdbxContent] to the KDBX inner XML. Protected string values are
/// XOR'd with [protectStream] **in document order** and base64-encoded; pass a
/// null stream only to emit an unprotected document (e.g. tests).
String writeXml(KdbxContent content, InnerRandomStream? protectStream) {
  final b = XmlBuilder();
  b.processing('xml', 'version="1.0" encoding="utf-8" standalone="yes"');
  b.element('KeePassFile', nest: () {
    b.element('Meta', nest: () {
      b.element('Generator', nest: () => b.text(content.meta.generator));
      b.element('DatabaseName', nest: () => b.text(content.meta.databaseName));
      b.element('MemoryProtection', nest: () {
        b.element('ProtectPassword', nest: () => b.text('True'));
      });
      _customData(b, content.meta.customData);
    });
    b.element('Root', nest: () => _group(b, content.root));
  });

  final doc = b.buildDocument();
  if (protectStream != null) {
    _transformProtectedInOrder(doc, protectStream, encrypt: true);
  }
  return doc.toXmlString();
}

void _group(XmlBuilder b, KdbxGroup g) {
  b.element('Group', nest: () {
    b.element('UUID', nest: () => b.text(base64.encode(g.uuid)));
    b.element('Name', nest: () => b.text(g.name));
    if (g.times != null) _times(b, g.times!);
    _customData(b, g.customData);
    for (final e in g.entries) {
      _entry(b, e);
    }
    for (final sub in g.groups) {
      _group(b, sub);
    }
  });
}

void _entry(XmlBuilder b, KdbxEntry e) {
  b.element('Entry', nest: () {
    b.element('UUID', nest: () => b.text(base64.encode(e.uuid)));
    if (e.tags.isNotEmpty) {
      b.element('Tags', nest: () => b.text(e.tags.join(';')));
    }
    if (e.times != null) _times(b, e.times!);
    e.strings.forEach((key, val) {
      b.element('String', nest: () {
        b.element('Key', nest: () => b.text(key));
        b.element('Value', nest: () {
          if (val.protected) b.attribute('Protected', 'True');
          b.text(val.value); // plaintext; encrypted in the post-pass
        });
      });
    });
    _customData(b, e.customData);
  });
}

void _times(XmlBuilder b, KdbxTimes t) {
  b.element('Times', nest: () {
    if (t.creation != null) {
      b.element('CreationTime',
          nest: () => b.text(encodeKdbxTime(t.creation!)));
    }
    if (t.lastModification != null) {
      b.element('LastModificationTime',
          nest: () => b.text(encodeKdbxTime(t.lastModification!)));
    }
    if (t.lastAccess != null) {
      b.element('LastAccessTime',
          nest: () => b.text(encodeKdbxTime(t.lastAccess!)));
    }
    if (t.expiry != null) {
      b.element('ExpiryTime', nest: () => b.text(encodeKdbxTime(t.expiry!)));
    }
    b.element('Expires', nest: () => b.text(t.expires ? 'True' : 'False'));
  });
}

void _customData(XmlBuilder b, Map<String, String> cd) {
  if (cd.isEmpty) return;
  b.element('CustomData', nest: () {
    cd.forEach((k, v) {
      b.element('Item', nest: () {
        b.element('Key', nest: () => b.text(k));
        b.element('Value', nest: () => b.text(v));
      });
    });
  });
}

/// Apply the inner stream to every `<Value Protected="True">` in document order.
void _transformProtectedInOrder(XmlDocument doc, InnerRandomStream stream,
    {required bool encrypt}) {
  for (final el in doc.descendants.whereType<XmlElement>()) {
    if (el.name.local != 'Value' || el.getAttribute('Protected') != 'True') {
      continue;
    }
    final text = el.innerText;
    final String out;
    if (encrypt) {
      out = base64.encode(stream.apply(Uint8List.fromList(utf8.encode(text))));
    } else {
      out = utf8.decode(stream.apply(base64.decode(text.trim())));
    }
    el.children
      ..clear()
      ..add(XmlText(out));
  }
}
