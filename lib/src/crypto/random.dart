import 'dart:math';
import 'dart:typed_data';

final Random _rng = Random.secure();

/// [n] cryptographically-secure random bytes (`Random.secure()` is a platform
/// CSPRNG). Used for master seeds, IVs, salts, and inner-stream keys.
Uint8List secureRandomBytes(int n) {
  final b = Uint8List(n);
  for (var i = 0; i < n; i++) {
    b[i] = _rng.nextInt(256);
  }
  return b;
}
