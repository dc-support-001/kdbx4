import 'dart:typed_data';

import '../kdbx_exceptions.dart';

/// Little-endian cursor over a byte buffer.
///
/// Every read advances the cursor; reading past the end throws
/// [KdbxFormatException] rather than returning garbage, so a truncated file is
/// reported as corrupt at the exact field that ran out.
class ByteReader {
  final Uint8List _data;
  int _pos = 0;

  ByteReader(this._data);
  ByteReader.fromList(List<int> data) : _data = Uint8List.fromList(data);

  int get position => _pos;
  int get remaining => _data.length - _pos;
  bool get hasMore => _pos < _data.length;

  void _need(int n) {
    if (n < 0 || _pos + n > _data.length) {
      throw KdbxFormatException(
          'unexpected end of data: need $n byte(s) at offset $_pos of ${_data.length}');
    }
  }

  int u8() {
    _need(1);
    return _data[_pos++];
  }

  int u16() {
    _need(2);
    final v =
        ByteData.sublistView(_data, _pos, _pos + 2).getUint16(0, Endian.little);
    _pos += 2;
    return v;
  }

  int u32() {
    _need(4);
    final v =
        ByteData.sublistView(_data, _pos, _pos + 4).getUint32(0, Endian.little);
    _pos += 4;
    return v;
  }

  int u64() {
    _need(8);
    final v =
        ByteData.sublistView(_data, _pos, _pos + 8).getUint64(0, Endian.little);
    _pos += 8;
    return v;
  }

  /// Returns a view of the next [n] bytes (no copy) and advances.
  Uint8List take(int n) {
    _need(n);
    final v = Uint8List.sublistView(_data, _pos, _pos + n);
    _pos += n;
    return v;
  }

  /// Returns a view of all remaining bytes and advances to the end.
  Uint8List takeRemaining() {
    final v = Uint8List.sublistView(_data, _pos);
    _pos = _data.length;
    return v;
  }

  /// View of the underlying buffer over `[start, end)`, independent of the
  /// cursor. Used to capture the exact outer-header bytes for header
  /// authentication (Phase 6).
  Uint8List range(int start, int end) =>
      Uint8List.sublistView(_data, start, end);
}
