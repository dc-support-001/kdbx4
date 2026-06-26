import 'dart:convert';
import 'dart:typed_data';

import '../io/byte_reader.dart';
import '../io/byte_writer.dart';

/// KDBX epoch: 0001-01-01T00:00:00Z (.NET `DateTime.MinValue`).
final DateTime _epoch = DateTime.utc(1, 1, 1);

/// Encode a timestamp in the KDBX4 binary form:
/// `base64( int64 LE seconds since 0001-01-01 )`.
String encodeKdbxTime(DateTime dt) {
  final seconds = dt.toUtc().difference(_epoch).inSeconds;
  return base64.encode((ByteWriter()..u64(seconds)).toBytes());
}

/// Decode a KDBX timestamp. Accepts the KDBX4 binary form and, for foreign /
/// KDBX 3.x files, an ISO-8601 string.
DateTime decodeKdbxTime(String value) {
  final s = value.trim();
  // An ISO-8601 datetime always has a ':' in its time part; base64 never does
  // ('T'/'-' are unreliable — 'T' is a valid base64 character).
  if (s.contains(':')) {
    return DateTime.parse(s).toUtc();
  }
  final bytes = Uint8List.fromList(base64.decode(s));
  final seconds = ByteReader(bytes).u64();
  return _epoch.add(Duration(seconds: seconds));
}
