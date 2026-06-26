import 'dart:typed_data';

/// Decode a hex string (whitespace ignored) to bytes.
Uint8List hex(String s) {
  final clean = s.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Lowercase hex of [bytes] (for readable failure messages / comparisons).
String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// [n] bytes all equal to [byte].
Uint8List rep(int byte, int n) => Uint8List(n)..fillRange(0, n, byte);
