/// Exception taxonomy for the KDBX layer.
///
/// More specific types (WrongCredentials, UnsupportedCipher, …) are added in
/// later phases; Phase 0/1 only needs the structural/format error.
library;

/// Thrown when bytes are malformed or truncated — a corrupt or non-KDBX input.
class KdbxFormatException implements Exception {
  final String message;
  KdbxFormatException(this.message);

  @override
  String toString() => 'KdbxFormatException: $message';
}

/// Thrown when a file uses a KDF we don't implement (by its `$UUID`).
class UnsupportedKdfException implements Exception {
  final List<int> uuid;
  UnsupportedKdfException(this.uuid);

  @override
  String toString() =>
      'UnsupportedKdfException: ${uuid.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
}

/// Thrown when a file uses an outer cipher we don't implement.
class UnsupportedCipherException implements Exception {
  final List<int> uuid;
  UnsupportedCipherException(this.uuid);

  @override
  String toString() =>
      'UnsupportedCipherException: ${uuid.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
}

/// Thrown when an authentication tag fails — a corrupt or tampered vault.
/// (A failed *header* HMAC means wrong credentials; see [WrongCredentialsException].)
class KdbxIntegrityException implements Exception {
  final String message;
  KdbxIntegrityException(this.message);

  @override
  String toString() => 'KdbxIntegrityException: $message';
}

/// Thrown when the master credentials don't unlock the vault — surfaced as the
/// header-HMAC mismatch (an authenticated wrong-key check, not a guess oracle).
class WrongCredentialsException implements Exception {
  @override
  String toString() => 'WrongCredentialsException: wrong password or key';
}
