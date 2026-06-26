import 'dart:convert';
import 'dart:typed_data';

import '../crypto/hashes.dart';
import '../io/byte_writer.dart';

/// The KDBX **composite key**: `SHA-256` of the concatenation of each
/// credential component, in order. Every component is 32 bytes —
/// password = `SHA-256(utf8)`, keyfile/hardware contribute their own 32-byte
/// value. v1 is password-only; keyfile and hardware-key components plug in
/// here unchanged (§5.1).
class Credentials {
  final List<Uint8List> _components = <Uint8List>[];

  Credentials();
  Credentials.password(String password) {
    addPassword(password);
  }

  void addPassword(String password) =>
      _components.add(sha256(utf8.encode(password)));

  /// Add an already-resolved 32-byte component (keyfile hash, challenge-response).
  void addKeyComponent(Uint8List component32) {
    if (component32.length != 32) {
      throw ArgumentError('credential component must be 32 bytes');
    }
    _components.add(Uint8List.fromList(component32));
  }

  bool get isEmpty => _components.isEmpty;

  /// Overwrite every component's bytes with zeros and drop them, so the
  /// composite-key material cannot be recovered from memory (lock flow, §5).
  void zeroize() {
    for (final c in _components) {
      c.fillRange(0, c.length, 0);
    }
    _components.clear();
  }

  Uint8List compositeKey() {
    final w = ByteWriter();
    for (final c in _components) {
      w.bytes(c);
    }
    return sha256(w.toBytes());
  }
}
