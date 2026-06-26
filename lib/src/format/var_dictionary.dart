import 'dart:convert';
import 'dart:typed_data';

import '../io/byte_reader.dart';
import '../io/byte_writer.dart';
import '../kdbx_exceptions.dart';

/// KDBX4 **VarDictionary** — the typed key/value structure used for KDF
/// parameters (header field 11) and public custom data (field 12).
///
/// Wire format: `u16 version (0x0100)`, then entries
/// `[u8 type, u32 keyLen, key(utf8), u32 valLen, value]`, terminated by a
/// `u8 type == 0`. Insertion order is preserved so a decode→encode round-trips
/// byte-for-byte against a foreign file.
class VarDictionary {
  static const int typeUInt32 = 0x04;
  static const int typeUInt64 = 0x05;
  static const int typeBool = 0x08;
  static const int typeInt32 = 0x0C;
  static const int typeInt64 = 0x0D;
  static const int typeString = 0x18;
  static const int typeBytes = 0x42;

  static const int _versionWord = 0x0100; // major 1, minor 0

  final Map<String, _Entry> _m = <String, _Entry>{};

  VarDictionary();

  Iterable<String> get keys => _m.keys;
  bool contains(String key) => _m.containsKey(key);
  int? typeOf(String key) => _m[key]?.type;

  Object? _typed(String key, int type) {
    final e = _m[key];
    if (e == null) return null;
    if (e.type != type) {
      throw KdbxFormatException(
          'VarDictionary "$key" has type ${e.type}, expected $type');
    }
    return e.value;
  }

  int? getUint32(String key) => _typed(key, typeUInt32) as int?;
  int? getUint64(String key) => _typed(key, typeUInt64) as int?;
  bool? getBool(String key) => _typed(key, typeBool) as bool?;
  int? getInt32(String key) => _typed(key, typeInt32) as int?;
  int? getInt64(String key) => _typed(key, typeInt64) as int?;
  String? getString(String key) => _typed(key, typeString) as String?;
  Uint8List? getBytes(String key) => _typed(key, typeBytes) as Uint8List?;

  void setUint32(String key, int v) => _m[key] = _Entry(typeUInt32, v);
  void setUint64(String key, int v) => _m[key] = _Entry(typeUInt64, v);
  void setBool(String key, bool v) => _m[key] = _Entry(typeBool, v);
  void setInt32(String key, int v) => _m[key] = _Entry(typeInt32, v);
  void setInt64(String key, int v) => _m[key] = _Entry(typeInt64, v);
  void setString(String key, String v) => _m[key] = _Entry(typeString, v);
  void setBytes(String key, Uint8List v) => _m[key] = _Entry(typeBytes, v);

  Uint8List encode() {
    final w = ByteWriter()..u16(_versionWord);
    _m.forEach((key, e) {
      w.u8(e.type);
      final kb = utf8.encode(key);
      w.u32(kb.length);
      w.bytes(kb);
      final vb = _encodeValue(e);
      w.u32(vb.length);
      w.bytes(vb);
    });
    w.u8(0x00);
    return w.toBytes();
  }

  static Uint8List _encodeValue(_Entry e) {
    final w = ByteWriter();
    switch (e.type) {
      case typeUInt32:
      case typeInt32:
        w.u32(e.value as int);
        break;
      case typeUInt64:
      case typeInt64:
        w.u64(e.value as int);
        break;
      case typeBool:
        w.u8((e.value as bool) ? 1 : 0);
        break;
      case typeString:
        w.bytes(utf8.encode(e.value as String));
        break;
      case typeBytes:
        w.bytes(e.value as Uint8List);
        break;
      default:
        throw KdbxFormatException('VarDictionary cannot encode type ${e.type}');
    }
    return w.toBytes();
  }

  factory VarDictionary.decode(Uint8List bytes) {
    final r = ByteReader(bytes);
    final version = r.u16();
    if ((version >> 8) != 1) {
      throw KdbxFormatException(
          'unsupported VarDictionary version 0x${version.toRadixString(16)}');
    }
    final vd = VarDictionary();
    while (true) {
      final type = r.u8();
      if (type == 0x00) break;
      final key = utf8.decode(r.take(r.u32()));
      final value = r.take(r.u32());
      vd._m[key] = _Entry(type, _decodeValue(type, value));
    }
    return vd;
  }

  static Object _decodeValue(int type, Uint8List b) {
    switch (type) {
      case typeUInt32:
        return ByteData.sublistView(b).getUint32(0, Endian.little);
      case typeInt32:
        return ByteData.sublistView(b).getInt32(0, Endian.little);
      case typeUInt64:
        return ByteData.sublistView(b).getUint64(0, Endian.little);
      case typeInt64:
        return ByteData.sublistView(b).getInt64(0, Endian.little);
      case typeBool:
        return b.isNotEmpty && b[0] != 0;
      case typeString:
        return utf8.decode(b);
      case typeBytes:
        return Uint8List.fromList(b);
      default:
        throw KdbxFormatException('VarDictionary unknown type $type');
    }
  }
}

class _Entry {
  final int type;
  final Object value;
  _Entry(this.type, this.value);
}
