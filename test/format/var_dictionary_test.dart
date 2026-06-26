import 'package:test/test.dart';
import 'package:kdbx4/src/format/var_dictionary.dart';
import 'package:kdbx4/src/kdbx_exceptions.dart';

import '../test_util.dart';

void main() {
  group('VarDictionary round-trip', () {
    test('all value types', () {
      final vd = VarDictionary()
        ..setUint32('u32', 0xDEADBEEF)
        ..setUint64('u64', 0x0102030405060708)
        ..setInt32('i32', -5)
        ..setInt64('i64', -123456789012)
        ..setBool('bT', true)
        ..setBool('bF', false)
        ..setString('str', 'héllo')
        ..setBytes('byt', hex('00ff8040'));

      final decoded = VarDictionary.decode(vd.encode());
      expect(decoded.getUint32('u32'), 0xDEADBEEF);
      expect(decoded.getUint64('u64'), 0x0102030405060708);
      expect(decoded.getInt32('i32'), -5);
      expect(decoded.getInt64('i64'), -123456789012);
      expect(decoded.getBool('bT'), true);
      expect(decoded.getBool('bF'), false);
      expect(decoded.getString('str'), 'héllo');
      expect(toHex(decoded.getBytes('byt')!), '00ff8040');
    });

    test('encode is canonical/idempotent', () {
      final vd = VarDictionary()
        ..setBytes(r'$UUID', hex('ef636ddf8c29444b91f7a9a403e30a0c'))
        ..setUint32('P', 1)
        ..setUint64('M', 16 * 1024 * 1024)
        ..setUint64('I', 3)
        ..setUint32('V', 0x13);
      final once = vd.encode();
      final twice = VarDictionary.decode(once).encode();
      expect(toHex(twice), toHex(once));
    });

    test('missing key returns null; wrong-type access throws', () {
      final vd = VarDictionary()..setUint32('x', 7);
      expect(vd.getUint32('nope'), isNull);
      expect(() => vd.getUint64('x'), throwsA(isA<KdbxFormatException>()));
    });
  });
}
