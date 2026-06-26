import 'dart:typed_data';

import '../crypto/aes_kdf.dart';
import '../crypto/argon2.dart';
import '../format/var_dictionary.dart';
import '../kdbx_exceptions.dart';

/// KDF `$UUID`s (KeePass KdfPool).
final Uint8List kdfArgon2d = Uint8List.fromList([
  0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, //
  0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
]);
final Uint8List kdfArgon2id = Uint8List.fromList([
  0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, //
  0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
]);
final Uint8List kdfAes = Uint8List.fromList([
  0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, //
  0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
]);

/// A configured key-derivation function: turns the composite key into the
/// 32-byte transformed key. Construct from a file's header params via
/// [Kdf.fromVarDict]; serialize our own via [toVarDict].
abstract class Kdf {
  Uint8List transform(Uint8List compositeKey);
  VarDictionary toVarDict();

  factory Kdf.fromVarDict(VarDictionary p) {
    final uuid = p.getBytes(r'$UUID');
    if (uuid == null) {
      throw KdbxFormatException(r'KDF parameters missing $UUID');
    }
    if (_eq(uuid, kdfArgon2id) || _eq(uuid, kdfArgon2d)) {
      return Argon2Kdf(
        type: _eq(uuid, kdfArgon2id) ? Argon2Type.id : Argon2Type.d,
        salt: p.getBytes('S')!,
        memoryKiB: p.getUint64('M')! ~/ 1024, // KDBX stores M in bytes
        iterations: p.getUint64('I')!,
        parallelism: p.getUint32('P')!,
        version: p.getUint32('V')!,
        secret: p.getBytes('K'),
        additional: p.getBytes('A'),
      );
    }
    if (_eq(uuid, kdfAes)) {
      return AesKdf(seed: p.getBytes('S')!, rounds: p.getUint64('R')!);
    }
    throw UnsupportedKdfException(uuid);
  }
}

/// Argon2 (id/d). Sesame writes Argon2id at 64 MiB / t=3 / p=1 (decision §13).
class Argon2Kdf implements Kdf {
  final Argon2Type type;
  final Uint8List salt;
  final int memoryKiB;
  final int iterations;
  final int parallelism;
  final int version;
  final Uint8List? secret;
  final Uint8List? additional;

  Argon2Kdf({
    required this.type,
    required this.salt,
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
    this.version = argon2Version13,
    this.secret,
    this.additional,
  });

  /// Sesame's default write configuration.
  Argon2Kdf.sesameDefault(this.salt)
      : type = Argon2Type.id,
        memoryKiB = 64 * 1024,
        iterations = 3,
        parallelism = 1,
        version = argon2Version13,
        secret = null,
        additional = null;

  @override
  Uint8List transform(Uint8List compositeKey) => argon2(
        type: type,
        password: compositeKey,
        salt: salt,
        memoryKiB: memoryKiB,
        iterations: iterations,
        parallelism: parallelism,
        version: version,
        secret: secret,
        additional: additional,
      );

  @override
  VarDictionary toVarDict() {
    final vd = VarDictionary()
      ..setBytes(r'$UUID', type == Argon2Type.id ? kdfArgon2id : kdfArgon2d)
      ..setBytes('S', salt)
      ..setUint32('P', parallelism)
      ..setUint64('M', memoryKiB * 1024)
      ..setUint64('I', iterations)
      ..setUint32('V', version);
    if (secret != null) vd.setBytes('K', secret!);
    if (additional != null) vd.setBytes('A', additional!);
    return vd;
  }
}

/// Legacy AES-KDF (read path for foreign KDBX4 files).
class AesKdf implements Kdf {
  final Uint8List seed;
  final int rounds;
  AesKdf({required this.seed, required this.rounds});

  @override
  Uint8List transform(Uint8List compositeKey) =>
      aesKdfTransform(compositeKey, seed, rounds);

  @override
  VarDictionary toVarDict() => VarDictionary()
    ..setBytes(r'$UUID', kdfAes)
    ..setUint64('R', rounds)
    ..setBytes('S', seed);
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
