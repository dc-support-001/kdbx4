import 'dart:io';
import 'dart:typed_data';

/// gzip (RFC 1952) wrappers — KDBX4 compresses the inner payload when the
/// outer header's compression flag is 1. Uses `dart:io`'s codec (native on our
/// iOS/macOS targets); produces output KeePassXC reads and vice-versa.
Uint8List gzipCompress(List<int> data) => Uint8List.fromList(gzip.encode(data));

Uint8List gzipDecompress(List<int> data) =>
    Uint8List.fromList(gzip.decode(data));
