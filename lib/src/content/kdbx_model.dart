import 'dart:typed_data';

/// A KDBX-level content model — the structure that lives in the inner XML.
/// Phase 8 maps this to/from the app's `Entry`/`Snapshot` domain model; the XML
/// reader/writer (this phase) map it to/from bytes. Keeping it separate stops
/// KDBX format concerns leaking into the app domain.

class KdbxStringValue {
  final String value;
  final bool protected;
  const KdbxStringValue(this.value, {this.protected = false});
}

class KdbxTimes {
  DateTime? creation;
  DateTime? lastModification;
  DateTime? lastAccess;
  DateTime? expiry;
  bool expires;
  KdbxTimes({
    this.creation,
    this.lastModification,
    this.lastAccess,
    this.expiry,
    this.expires = false,
  });
}

class KdbxEntry {
  Uint8List uuid; // 16 bytes
  Map<String, KdbxStringValue> strings;
  List<String> tags;
  KdbxTimes? times;
  Map<String, String> customData;

  KdbxEntry({
    required this.uuid,
    Map<String, KdbxStringValue>? strings,
    List<String>? tags,
    this.times,
    Map<String, String>? customData,
  })  : strings = strings ?? <String, KdbxStringValue>{},
        tags = tags ?? <String>[],
        customData = customData ?? <String, String>{};
}

class KdbxGroup {
  Uint8List uuid;
  String name;
  KdbxTimes? times;
  Map<String, String> customData;
  List<KdbxEntry> entries;
  List<KdbxGroup> groups;

  KdbxGroup({
    required this.uuid,
    required this.name,
    this.times,
    Map<String, String>? customData,
    List<KdbxEntry>? entries,
    List<KdbxGroup>? groups,
  })  : customData = customData ?? <String, String>{},
        entries = entries ?? <KdbxEntry>[],
        groups = groups ?? <KdbxGroup>[];
}

class KdbxMeta {
  String generator;
  String databaseName;
  Map<String, String> customData; // database-level CustomData
  KdbxMeta({
    this.generator = 'Sesame PS',
    this.databaseName = '',
    Map<String, String>? customData,
  }) : customData = customData ?? <String, String>{};
}

class KdbxContent {
  KdbxMeta meta;
  KdbxGroup root;
  KdbxContent({required this.meta, required this.root});
}
