import 'dart:typed_data';

/// Little-endian byte buffer builder.
///
/// KDBX stores all integers little-endian; this is the single place that
/// encoding lives so the rest of the layer never touches [ByteData] directly.
class ByteWriter {
  final BytesBuilder _b = BytesBuilder(copy: false);

  void u8(int v) => _b.addByte(v & 0xff);

  void u16(int v) => _b
      .add((ByteData(2)..setUint16(0, v, Endian.little)).buffer.asUint8List());

  void u32(int v) => _b
      .add((ByteData(4)..setUint32(0, v, Endian.little)).buffer.asUint8List());

  void u64(int v) => _b
      .add((ByteData(8)..setUint64(0, v, Endian.little)).buffer.asUint8List());

  void bytes(List<int> v) => _b.add(v);

  int get length => _b.length;

  Uint8List toBytes() => _b.toBytes();
}
