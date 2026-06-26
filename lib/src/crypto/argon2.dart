import 'dart:typed_data';

import 'package:pointycastle/export.dart';

enum Argon2Type { d, id }

const int argon2Version13 = 0x13;

/// Argon2 key derivation (variants `d` and `id`).
///
/// [memoryKiB] is in kibibytes (KDBX stores it in bytes — convert at the
/// header boundary, not here). Sesame writes Argon2**id** at 64 MiB / t=3 / p=1
/// (decision §13); the read path also derives `d` for foreign files.
Uint8List argon2({
  required Argon2Type type,
  required Uint8List password,
  required Uint8List salt,
  required int memoryKiB,
  required int iterations,
  required int parallelism,
  int version = argon2Version13,
  int length = 32,
  Uint8List? secret,
  Uint8List? additional,
}) {
  final params = Argon2Parameters(
    type == Argon2Type.id
        ? Argon2Parameters.ARGON2_id
        : Argon2Parameters.ARGON2_d,
    salt,
    desiredKeyLength: length,
    secret: secret,
    additional: additional,
    iterations: iterations,
    memory: memoryKiB,
    lanes: parallelism,
    version: version,
  );
  final gen = Argon2BytesGenerator()..init(params);
  final out = Uint8List(length);
  gen.deriveKey(password, 0, out, 0);
  return out;
}
