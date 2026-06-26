import 'package:test/test.dart';
import 'package:kdbx4/src/format/inner_header.dart';
import 'package:kdbx4/src/io/byte_reader.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  test('round-trip with ChaCha20 stream + binaries', () {
    final ih = InnerHeader(
      streamId: 3,
      streamKey: rep(0x5A, 64),
      binaries: [
        KdbxBinary(false, hex('cafebabe')),
        KdbxBinary(true, hex('0011223344')),
      ],
    );
    final parsed = InnerHeader.parse(ByteReader(ih.serialize()));

    expect(parsed.streamId, 3);
    expect(toHex(parsed.streamKey), toHex(rep(0x5A, 64)));
    expect(parsed.binaries.length, 2);
    expect(parsed.binaries[0].memoryProtected, false);
    expect(toHex(parsed.binaries[0].data), 'cafebabe');
    expect(parsed.binaries[1].memoryProtected, true);
    expect(toHex(parsed.binaries[1].data), '0011223344');
  });

  test('round-trip with no binaries', () {
    final ih = InnerHeader(streamId: 2, streamKey: rep(0x01, 32));
    final parsed = InnerHeader.parse(ByteReader(ih.serialize()));
    expect(parsed.streamId, 2);
    expect(parsed.binaries, isEmpty);
  });

  test('missing stream id/key throws', () {
    // Only an end-of-header marker (id 0, size 0).
    expect(() => InnerHeader.parse(ByteReader.fromList([0, 0, 0, 0, 0])),
        throwsA(isA<KdbxFormatException>()));
  });
}
