import 'dart:typed_data';

import '../crypto/hmac.dart';
import '../io/byte_reader.dart';
import '../io/byte_writer.dart';
import '../kdbx_exceptions.dart';
import '../keys/key_schedule.dart';

/// KDBX4 **HMAC block stream** — the authenticated framing wrapped around the
/// ciphertext body. Each block is `HMAC(32) ‖ len(u32 LE) ‖ data`, where the
/// HMAC (keyed by [blockHmacKey] for the block's index) covers
/// `u64LE(index) ‖ u32LE(len) ‖ data`. A final zero-length block terminates
/// the stream (and is itself authenticated). Verifying each block's HMAC is
/// what makes tampering detectable.
class HmacBlockStream {
  static const int blockSize = 1024 * 1024;

  static Uint8List write(Uint8List data, Uint8List hmacBase) {
    final w = ByteWriter();
    var index = 0;
    var off = 0;
    while (off < data.length) {
      final n = (data.length - off) < blockSize ? data.length - off : blockSize;
      _emit(w, index, Uint8List.sublistView(data, off, off + n), hmacBase);
      off += n;
      index++;
    }
    _emit(w, index, Uint8List(0), hmacBase); // terminator
    return w.toBytes();
  }

  static void _emit(
      ByteWriter w, int index, Uint8List block, Uint8List hmacBase) {
    final key = blockHmacKey(hmacBase, index);
    final mac = hmacSha256(
        key,
        (ByteWriter()
              ..u64(index)
              ..u32(block.length)
              ..bytes(block))
            .toBytes());
    w
      ..bytes(mac)
      ..u32(block.length)
      ..bytes(block);
  }

  /// Read + authenticate [framed] (positioned at the first block) and return
  /// the concatenated payload. Throws [KdbxIntegrityException] on a bad HMAC.
  static Uint8List read(Uint8List framed, Uint8List hmacBase) {
    final r = ByteReader(framed);
    final out = ByteWriter();
    var index = 0;
    while (true) {
      final mac = r.take(32);
      final n = r.u32();
      final block = r.take(n);
      final expected = hmacSha256(
          blockHmacKey(hmacBase, index),
          (ByteWriter()
                ..u64(index)
                ..u32(n)
                ..bytes(block))
              .toBytes());
      if (!_constantTimeEq(mac, expected)) {
        throw KdbxIntegrityException('HMAC mismatch at block $index');
      }
      if (n == 0) break;
      out.bytes(block);
      index++;
    }
    return out.toBytes();
  }
}

bool _constantTimeEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
