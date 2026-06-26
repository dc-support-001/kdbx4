import 'dart:typed_data';

import '../io/byte_reader.dart';
import '../io/byte_writer.dart';
import '../kdbx_exceptions.dart';

/// A KDBX4 binary pool entry (attachment), referenced from XML by index.
class KdbxBinary {
  final bool memoryProtected;
  final Uint8List data;
  KdbxBinary(this.memoryProtected, this.data);
}

/// The KDBX4 **inner header** — the first bytes of the decrypted (and
/// decompressed) payload, before the XML. Carries the inner-random-stream
/// cipher used to protect in-memory fields, plus the binary pool.
class InnerHeader {
  static const int fEnd = 0;
  static const int fStreamId = 1; // 2 = Salsa20, 3 = ChaCha20
  static const int fStreamKey = 2;
  static const int fBinary = 3;

  int streamId;
  Uint8List streamKey;
  List<KdbxBinary> binaries;

  InnerHeader({
    required this.streamId,
    required this.streamKey,
    List<KdbxBinary>? binaries,
  }) : binaries = binaries ?? <KdbxBinary>[];

  factory InnerHeader.parse(ByteReader r) {
    int? streamId;
    Uint8List? streamKey;
    final binaries = <KdbxBinary>[];

    while (true) {
      final id = r.u8();
      final data = r.take(r.u32());
      if (id == fEnd) break;
      switch (id) {
        case fStreamId:
          streamId = ByteData.sublistView(data).getUint32(0, Endian.little);
          break;
        case fStreamKey:
          streamKey = Uint8List.fromList(data);
          break;
        case fBinary:
          final protected = data.isNotEmpty && (data[0] & 0x01) != 0;
          binaries.add(KdbxBinary(
              protected,
              Uint8List.fromList(
                  Uint8List.sublistView(data, data.isEmpty ? 0 : 1))));
          break;
      }
    }

    if (streamId == null || streamKey == null) {
      throw KdbxFormatException('inner header missing stream id/key');
    }
    return InnerHeader(
        streamId: streamId, streamKey: streamKey, binaries: binaries);
  }

  Uint8List serialize() {
    final w = ByteWriter();
    void field(int id, List<int> data) {
      w.u8(id);
      w.u32(data.length);
      w.bytes(data);
    }

    field(fStreamId, (ByteWriter()..u32(streamId)).toBytes());
    field(fStreamKey, streamKey);
    for (final b in binaries) {
      final bw = ByteWriter()
        ..u8(b.memoryProtected ? 0x01 : 0x00)
        ..bytes(b.data);
      field(fBinary, bw.toBytes());
    }
    field(fEnd, const []);
    return w.toBytes();
  }
}
