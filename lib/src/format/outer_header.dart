import 'dart:typed_data';

import '../io/byte_reader.dart';
import '../io/byte_writer.dart';
import '../kdbx_exceptions.dart';
import 'var_dictionary.dart';

/// The KDBX4 unencrypted **outer header**: signatures, format version, and the
/// TLV fields that tell us how to derive the key and decrypt the body.
///
/// We only support KDBX major version 4 (decision §13: write 4.0, read 4.0/4.1).
class OuterHeader {
  static const int sig1 = 0x9AA2D903;
  static const int sig2 = 0xB54BFB67;

  static const int fEndOfHeader = 0;
  static const int fComment = 1;
  static const int fCipherId = 2;
  static const int fCompression = 3;
  static const int fMasterSeed = 4;
  static const int fEncryptionIV = 7;
  static const int fKdfParameters = 11;
  static const int fPublicCustomData = 12;

  int versionMajor;
  int versionMinor;
  Uint8List cipherId; // 16-byte cipher UUID
  int compression; // 0 = none, 1 = gzip
  Uint8List masterSeed; // 32 bytes
  Uint8List encryptionIV;
  VarDictionary kdfParameters;
  Uint8List? publicCustomData;

  /// On parse: the exact header byte range (offset 0 .. end of the
  /// EndOfHeader field) — needed verbatim for the header SHA-256 + HMAC in
  /// Phase 6. Null when the header is built in memory.
  Uint8List? rawBytes;

  OuterHeader({
    this.versionMajor = 4,
    this.versionMinor = 0,
    required this.cipherId,
    required this.compression,
    required this.masterSeed,
    required this.encryptionIV,
    required this.kdfParameters,
    this.publicCustomData,
    this.rawBytes,
  });

  factory OuterHeader.parse(ByteReader r) {
    final start = r.position;
    if (r.u32() != sig1 || r.u32() != sig2) {
      throw KdbxFormatException('not a KDBX file (bad signature)');
    }
    final minor = r.u16();
    final major = r.u16();
    if (major != 4) {
      throw KdbxFormatException(
          'unsupported KDBX major version $major (need 4)');
    }

    Uint8List? cipher, seed, iv, pcd;
    int? compression;
    VarDictionary? kdf;

    while (true) {
      final id = r.u8();
      final data = r.take(r.u32());
      if (id == fEndOfHeader) break;
      switch (id) {
        case fCipherId:
          cipher = Uint8List.fromList(data);
          break;
        case fCompression:
          compression = ByteData.sublistView(data).getUint32(0, Endian.little);
          break;
        case fMasterSeed:
          seed = Uint8List.fromList(data);
          break;
        case fEncryptionIV:
          iv = Uint8List.fromList(data);
          break;
        case fKdfParameters:
          kdf = VarDictionary.decode(Uint8List.fromList(data));
          break;
        case fPublicCustomData:
          pcd = Uint8List.fromList(data);
          break;
        // fComment and unknown ids are ignored.
      }
    }

    if (cipher == null ||
        compression == null ||
        seed == null ||
        iv == null ||
        kdf == null) {
      throw KdbxFormatException('outer header missing a mandatory field');
    }

    return OuterHeader(
      versionMajor: major,
      versionMinor: minor,
      cipherId: cipher,
      compression: compression,
      masterSeed: seed,
      encryptionIV: iv,
      kdfParameters: kdf,
      publicCustomData: pcd,
      rawBytes: r.range(start, r.position),
    );
  }

  Uint8List serialize() {
    final w = ByteWriter()
      ..u32(sig1)
      ..u32(sig2)
      ..u16(versionMinor)
      ..u16(versionMajor);

    void field(int id, List<int> data) {
      w.u8(id);
      w.u32(data.length);
      w.bytes(data);
    }

    field(fCipherId, cipherId);
    field(fCompression, (ByteWriter()..u32(compression)).toBytes());
    field(fMasterSeed, masterSeed);
    field(fEncryptionIV, encryptionIV);
    field(fKdfParameters, kdfParameters.encode());
    if (publicCustomData != null) {
      field(fPublicCustomData, publicCustomData!);
    }
    field(fEndOfHeader, const [0x0d, 0x0a, 0x0d, 0x0a]);
    return w.toBytes();
  }
}
