import 'dart:convert';
import 'dart:typed_data';

import 'content/inner_random_stream.dart';
import 'content/kdbx_model.dart';
import 'content/xml_reader.dart';
import 'content/xml_writer.dart';
import 'crypto/hashes.dart';
import 'crypto/hmac.dart';
import 'crypto/random.dart';
import 'format/inner_header.dart';
import 'format/outer_header.dart';
import 'io/byte_reader.dart';
import 'io/byte_writer.dart';
import 'kdbx_exceptions.dart';
import 'keys/credentials.dart';
import 'keys/kdf.dart';
import 'keys/key_schedule.dart';
import 'payload/cipher.dart';
import 'payload/gzip.dart';
import 'payload/hmac_block_stream.dart';

const int compressionNone = 0;
const int compressionGzip = 1;

/// An open KDBX database: the decrypted [content] plus the configuration needed
/// to re-save it faithfully. Caches the **transformed key** so repeated saves
/// don't re-run the (expensive) KDF — each save still regenerates the master
/// seed/IV/inner-key, so freshness is preserved while the KDF salt stays put.
class KdbxDatabase {
  KdbxContent content;
  final Kdf kdf;
  final Uint8List cipherId;
  final int compression;
  final int innerStreamId;
  final Uint8List transformedKey;

  /// Unencrypted outer-header PublicCustomData (KDBX field 12), carried verbatim
  /// across saves. Sesame stores the user-facing vault name here so it is
  /// readable without the passcode (see `repository/vault_name.dart`). Mutable so
  /// the name can be updated in place before a re-save.
  Uint8List? publicCustomData;

  KdbxDatabase({
    required this.content,
    required this.kdf,
    required this.cipherId,
    required this.compression,
    required this.innerStreamId,
    required this.transformedKey,
    this.publicCustomData,
  });

  /// Build a brand-new database (computes the transformed key once).
  factory KdbxDatabase.create({
    required KdbxContent content,
    required Kdf kdf,
    required Credentials credentials,
    Uint8List? cipherId,
    int compression = compressionGzip,
    int innerStreamId = innerStreamChaCha20,
    Uint8List? publicCustomData,
  }) =>
      KdbxDatabase(
        content: content,
        kdf: kdf,
        cipherId: cipherId ?? cipherAes256,
        compression: compression,
        innerStreamId: innerStreamId,
        transformedKey: kdf.transform(credentials.compositeKey()),
        publicCustomData: publicCustomData,
      );
}

/// Assembles and parses a complete KDBX4 file. Layout:
/// `[outer header][SHA-256(header)][HMAC-SHA-256(header)][HMAC block stream]`.
class KdbxFile {
  /// Serialize [content] into KDBX4 bytes (version **4.0**, §13). Supply either
  /// [credentials] (KDF is run) or a precomputed [transformedKey].
  static Uint8List write({
    required KdbxContent content,
    required Kdf kdf,
    Credentials? credentials,
    Uint8List? transformedKey,
    Uint8List? cipherId,
    int compression = compressionGzip,
    int innerStreamId = innerStreamChaCha20,
    Uint8List? masterSeed,
    Uint8List? encryptionIV,
    Uint8List? innerStreamKey,
    Uint8List? publicCustomData,
  }) {
    assert(credentials != null || transformedKey != null,
        'write needs credentials or a transformedKey');
    final cipher = cipherId ?? cipherAes256;
    final seed = masterSeed ?? secureRandomBytes(32);
    final iv = encryptionIV ?? secureRandomBytes(_ivLength(cipher));
    final streamKey = innerStreamKey ?? secureRandomBytes(64);

    final header = OuterHeader(
      versionMajor: 4,
      versionMinor: 0,
      cipherId: cipher,
      compression: compression,
      masterSeed: seed,
      encryptionIV: iv,
      kdfParameters: kdf.toVarDict(),
      publicCustomData: publicCustomData,
    );
    final headerBytes = header.serialize();

    final transformed =
        transformedKey ?? kdf.transform(credentials!.compositeKey());
    final dataKey = finalKey(seed, transformed);
    final hmacBase = hmacBaseKey(seed, transformed);

    final innerHeader =
        InnerHeader(streamId: innerStreamId, streamKey: streamKey);
    final xml =
        writeXml(content, InnerRandomStream.create(innerStreamId, streamKey));
    var payload = (ByteWriter()
          ..bytes(innerHeader.serialize())
          ..bytes(utf8.encode(xml)))
        .toBytes();
    if (compression == compressionGzip) {
      payload = gzipCompress(payload);
    }
    final ciphertext = OuterCipher.encrypt(cipher, dataKey, iv, payload);

    return (ByteWriter()
          ..bytes(headerBytes)
          ..bytes(sha256(headerBytes))
          ..bytes(hmacSha256(headerHmacKey(hmacBase), headerBytes))
          ..bytes(HmacBlockStream.write(ciphertext, hmacBase)))
        .toBytes();
  }

  /// Re-serialize an open [db] (uses the cached transformed key).
  static Uint8List serialize(KdbxDatabase db) => write(
        content: db.content,
        kdf: db.kdf,
        transformedKey: db.transformedKey,
        cipherId: db.cipherId,
        compression: db.compression,
        innerStreamId: db.innerStreamId,
        publicCustomData: db.publicCustomData,
      );

  /// Read **only** the unencrypted outer header and return its PublicCustomData
  /// (KDBX field 12), or null if absent. Requires no credentials and does not
  /// decrypt the body — used to read the vault name while the vault is locked.
  static Uint8List? peekPublicCustomData(Uint8List bytes) =>
      OuterHeader.parse(ByteReader(bytes)).publicCustomData;

  /// Parse + authenticate KDBX4 [bytes] into an open [KdbxDatabase].
  /// Throws [WrongCredentialsException] on a bad password,
  /// [KdbxIntegrityException] on corruption.
  static KdbxDatabase open({
    required Uint8List bytes,
    required Credentials credentials,
  }) {
    final r = ByteReader(bytes);
    final header = OuterHeader.parse(r);
    final headerBytes = header.rawBytes!;

    final storedSha = r.take(32);
    final storedHmac = r.take(32);
    if (!_eq(storedSha, sha256(headerBytes))) {
      throw KdbxIntegrityException('outer header SHA-256 mismatch (corrupt)');
    }

    final kdf = Kdf.fromVarDict(header.kdfParameters);
    final transformed = kdf.transform(credentials.compositeKey());
    final dataKey = finalKey(header.masterSeed, transformed);
    final hmacBase = hmacBaseKey(header.masterSeed, transformed);

    if (!_eq(storedHmac, hmacSha256(headerHmacKey(hmacBase), headerBytes))) {
      throw WrongCredentialsException();
    }

    final body = Uint8List.sublistView(bytes, r.position);
    final ciphertext = HmacBlockStream.read(body, hmacBase);
    var payload = OuterCipher.decrypt(
        header.cipherId, dataKey, header.encryptionIV, ciphertext);
    if (header.compression == compressionGzip) {
      payload = gzipDecompress(payload);
    }

    final pr = ByteReader(payload);
    final innerHeader = InnerHeader.parse(pr);
    final xml = utf8.decode(pr.takeRemaining());
    final content = readXml(xml,
        InnerRandomStream.create(innerHeader.streamId, innerHeader.streamKey));

    return KdbxDatabase(
      content: content,
      kdf: kdf,
      cipherId: header.cipherId,
      compression: header.compression,
      innerStreamId: innerHeader.streamId,
      transformedKey: transformed,
      publicCustomData: header.publicCustomData,
    );
  }

  /// Convenience: parse and return just the content.
  static KdbxContent read({
    required Uint8List bytes,
    required Credentials credentials,
  }) =>
      open(bytes: bytes, credentials: credentials).content;

  static int _ivLength(Uint8List cipherId) =>
      _eq(cipherId, cipherChaCha20) ? 12 : 16;
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
