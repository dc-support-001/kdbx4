import 'package:test/test.dart';
import 'package:kdbx4/src/format/kdbx_time.dart';

void main() {
  test('epoch encodes to all-zero base64 (FIX)', () {
    final epoch = DateTime.utc(1, 1, 1);
    expect(encodeKdbxTime(epoch), 'AAAAAAAAAAA=');
    expect(decodeKdbxTime('AAAAAAAAAAA='), epoch);
  });

  test('binary form round-trips to second precision', () {
    final dt = DateTime.utc(2026, 6, 2, 13, 45, 7);
    final decoded = decodeKdbxTime(encodeKdbxTime(dt));
    expect(decoded, dt);
  });

  test('tolerates ISO-8601 (KDBX 3.x / foreign)', () {
    expect(decodeKdbxTime('2022-03-04T05:06:07Z'),
        DateTime.utc(2022, 3, 4, 5, 6, 7));
  });
}
