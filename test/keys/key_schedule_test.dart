import 'package:test/test.dart';
import 'package:kdbx4/src/keys/key_schedule.dart';

import '../test_util.dart';

void main() {
  // Expected values precomputed with Python hashlib.
  group('key schedule KAT', () {
    final seed = rep(0x11, 32);
    final transformed = rep(0x22, 32);

    test('finalKey = SHA-256(seed ‖ T)', () {
      expect(toHex(finalKey(seed, transformed)),
          '5189c77d29fe5d546a045ec46986852785fea5c13ac7da9c115ff5fb6edf817c');
    });

    test('hmacBase = SHA-512(seed ‖ T ‖ 0x01)', () {
      expect(
          toHex(hmacBaseKey(seed, transformed)),
          'd0357d0d5d6eb95ef9c0bd0aa644597eea3e3060cc2579ae5ff3faee9eecca77'
          '1b83a4a811a574de7444cd7c102cab3d459baf0e3c32f53ec5fe31c9ff94a797');
    });
  });

  group('block HMAC keys KAT', () {
    final hmacBase = rep(0x33, 64);

    test('block 0', () {
      expect(
          toHex(blockHmacKey(hmacBase, 0)),
          'c40bc31d22c79d656ea454daa67ee6fd286e656c4f68152e021b6623a2a335bf'
          'baa9f2de52b8510310d0c9f89f864cc944c3659ee82f2f109669b85b229da907');
    });

    test('block 1', () {
      expect(
          toHex(blockHmacKey(hmacBase, 1)),
          '6dff1f5f9046aca828f1782115811e608c4493445b16195091aad387d7c33e0e'
          '3d3258d021dcfb0bf4a159d4424fbab4d992fb800ac3e114f8a4cce6c7f1aaf4');
    });

    test('header key (block index 0xFFFFFFFFFFFFFFFF)', () {
      expect(
          toHex(headerHmacKey(hmacBase)),
          '8b2defafad338c862818bf952cc3db3393829dc63bae3db211038916820a40df'
          'afa77b0d77bcd6d2f3e5031586af370d93f27c0ff6a25a6b96b866da36246ad3');
    });
  });
}
