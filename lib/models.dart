// Data types shared by the scanner, the risk engine, the AI helper and the UI.

/// How worried the app is about a connection.
enum RiskLevel { safe, suspicious, dangerous }

/// Which way a connection goes, from this PC's point of view.
enum Direction {
  /// This PC reached out to a remote computer.
  outgoing,

  /// A remote computer connected in to a program on this PC.
  incoming,

  /// A program is waiting for others to connect (an "open door").
  listening,

  /// Both ends are this same PC.
  local,

  /// Closing / leftover connections.
  other,
}

/// One network connection (or listening socket) owned by a process.
class NetConnection {
  const NetConnection({
    required this.protocol,
    required this.localAddress,
    required this.localPort,
    required this.remoteAddress,
    required this.remotePort,
    required this.state,
    required this.pid,
  });

  /// `TCP` or `UDP`.
  final String protocol;
  final String localAddress;
  final int localPort;

  /// Empty for UDP endpoints and listening sockets.
  final String remoteAddress;
  final int remotePort;

  /// `Established`, `Listen`, `Bound`, `TimeWait`, ...
  final String state;
  final int pid;

  String get key =>
      '$protocol|$localAddress|$localPort|$remoteAddress|$remotePort|$pid';

  bool get isTcp => protocol == 'TCP';
  bool get isListening => state == 'Listen' || (!isTcp && remotePort == 0);
  bool get isEstablished => state == 'Established';
}

/// A running program.
class ProcessInfo {
  const ProcessInfo({
    required this.pid,
    required this.name,
    this.path,
    this.commandLine,
    this.parentPid,
    this.started,
    this.services = const [],
  });

  final int pid;
  final String name;

  /// Full path of the program file, or null when Windows hides it.
  final String? path;
  final String? commandLine;
  final int? parentPid;

  /// When the program was started.
  final DateTime? started;

  /// Windows services running inside this program (friendly names).
  final List<String> services;

  ProcessInfo withPath(String? newPath) => ProcessInfo(
        pid: pid,
        name: name,
        path: newPath,
        commandLine: commandLine,
        parentPid: parentPid,
        started: started,
        services: services,
      );

  /// File name of the program, like `chrome.exe`.
  String get fileName {
    final p = path;
    return p != null && p.isNotEmpty ? fileNameOf(p) : name;
  }
}

/// One way a program is set to start by itself when Windows starts.
class AutostartEntry {
  const AutostartEntry({
    required this.kind,
    required this.name,
    required this.command,
    this.exePath,
    this.exeName = '',
    this.args = '',
  });

  /// `run` (startup list in the registry), `folder` (Startup folder),
  /// `task` (scheduled task) or `service` (Windows service).
  final String kind;
  final String name;
  final String command;

  /// Full path of the program it starts, when known.
  final String? exePath;

  /// Lower-case file name of the program it starts.
  final String exeName;

  /// Lower-case arguments it passes to the program.
  final String args;

  /// Stable id used to remember entries between runs.
  String get key => '$kind|$name|$command'.toLowerCase();

  /// Plain words for where the entry lives.
  String get where => switch (kind) {
        'run' => 'Windows startup list',
        'folder' => 'Startup folder',
        'task' => 'scheduled task',
        'service' => 'Windows service',
        _ => 'startup entry',
      };

  /// Short name without the task folder, like `Updater`.
  String get shortName {
    final i = name.lastIndexOf('\\');
    return i >= 0 && i < name.length - 1 ? name.substring(i + 1) : name;
  }
}

/// A program that keeps contacting the same address on a timer.
class RepeatInfo {
  const RepeatInfo({required this.count, required this.seconds});

  /// How many times it was seen.
  final int count;

  /// Roughly how many seconds between the contacts.
  final int seconds;
}

/// Result of checking a program's digital signature.
enum SignatureStatus {
  valid,
  notSigned,
  hashMismatch,
  notTrusted,
  unknownError,
  notSupported,
  unknown,
}

SignatureStatus parseSignatureStatus(String? raw) {
  switch ((raw ?? '').toLowerCase()) {
    case 'valid':
      return SignatureStatus.valid;
    case 'notsigned':
      return SignatureStatus.notSigned;
    case 'hashmismatch':
      return SignatureStatus.hashMismatch;
    case 'nottrusted':
      return SignatureStatus.notTrusted;
    case 'unknownerror':
      return SignatureStatus.unknownError;
    case 'notsupportedfileformat':
    case 'incompatible':
      return SignatureStatus.notSupported;
    default:
      return SignatureStatus.unknown;
  }
}

/// Facts about a program file on disk.
class FileInfo {
  const FileInfo({
    required this.path,
    required this.exists,
    this.signature = SignatureStatus.unknown,
    this.signer,
    this.company,
    this.product,
    this.description,
    this.created,
    this.size,
    this.checkError,
  });

  final String path;
  final bool exists;
  final SignatureStatus signature;
  final String? signer;
  final String? company;
  final String? product;
  final String? description;
  final DateTime? created;
  final int? size;

  /// Why the signature couldn't be checked (for troubleshooting).
  final String? checkError;

  bool get isSigned => signature == SignatureStatus.valid;
}

/// Who owns an IP address and where it is.
class GeoInfo {
  const GeoInfo({
    required this.ip,
    this.country,
    this.countryCode,
    this.city,
    this.isp,
    this.org,
    this.asName,
    this.proxy = false,
    this.hosting = false,
  });

  final String ip;
  final String? country;
  final String? countryCode;
  final String? city;
  final String? isp;
  final String? org;
  final String? asName;

  /// The IP belongs to a VPN, proxy or Tor service.
  final bool proxy;

  /// The IP belongs to a data center / hosting company.
  final bool hosting;

  /// Best short name for who owns the IP.
  String? get owner {
    for (final v in [org, isp, asName]) {
      if (v != null && v.trim().isNotEmpty) return v.trim();
    }
    return null;
  }
}

/// What kind of clue a [RiskReason] is.
enum ReasonKind {
  folder,
  signature,
  disguise,
  tool,
  command,
  port,
  network,
  country,
  file,

  /// How the program was started (for example by a document).
  behavior,

  /// It starts by itself with Windows.
  startup,

  /// Remote control of this PC.
  remote,
}

/// One warning clue that adds to a connection's risk score.
class RiskReason {
  const RiskReason({
    required this.kind,
    required this.title,
    required this.detail,
    required this.points,
  });

  final ReasonKind kind;
  final String title;
  final String detail;
  final int points;
}

class RiskAssessment {
  const RiskAssessment({
    required this.score,
    this.reasons = const [],
    this.goodSigns = const [],
    this.notes = const [],
  });

  static const safeScore = RiskAssessment(score: 0);

  final int score;

  /// Why it looks suspicious (each clue adds points).
  final List<RiskReason> reasons;

  /// Short reasons why it looks fine, like "Made by Google LLC (signed)".
  final List<String> goodSigns;

  /// Friendly info lines that don't change the score.
  final List<String> notes;

  RiskLevel get level => levelForScore(score);

  static RiskLevel levelForScore(int score) {
    if (score >= 50) return RiskLevel.dangerous;
    if (score >= 20) return RiskLevel.suspicious;
    return RiskLevel.safe;
  }
}

/// The AI's opinion about a connection.
enum AiRating { safe, suspicious, dangerous, unknown }

class AiVerdict {
  const AiVerdict({
    required this.rating,
    required this.confidence,
    required this.summary,
    required this.advice,
    required this.provider,
    required this.model,
    required this.time,
    this.error,
  });

  factory AiVerdict.failed(String error,
          {required String provider, required String model}) =>
      AiVerdict(
        rating: AiRating.unknown,
        confidence: 0,
        summary: '',
        advice: '',
        provider: provider,
        model: model,
        time: DateTime.now(),
        error: error,
      );

  final AiRating rating;
  final int confidence;
  final String summary;
  final String advice;
  final String provider;
  final String model;
  final DateTime time;
  final String? error;

  bool get isError => error != null;
}

/// Everything the UI shows for one connection.
class ConnectionRow {
  const ConnectionRow({
    required this.connection,
    required this.direction,
    required this.risk,
    required this.firstSeen,
    this.process,
    this.file,
    this.geo,
    this.isNew = false,
    this.ancestors = const [],
    this.autostarts = const [],
  });

  final NetConnection connection;
  final ProcessInfo? process;
  final FileInfo? file;
  final GeoInfo? geo;

  /// The programs that started this one: parent first, then grandparent...
  final List<ProcessInfo> ancestors;

  /// Ways this program starts by itself with Windows.
  final List<AutostartEntry> autostarts;
  final RiskAssessment risk;
  final Direction direction;
  final DateTime firstSeen;
  final bool isNew;

  int get pid => connection.pid;
  String? get path => process?.path;
  String? get folder => folderOf(path);

  String get fileName {
    final p = path;
    if (p != null && p.isNotEmpty) return fileNameOf(p);
    final name = process?.name;
    if (name != null && name.isNotEmpty) return name;
    if (pid == 0) return 'System Idle Process';
    if (pid == 4) return 'System';
    return 'Program #$pid';
  }

  /// Is this Windows itself (the kernel), which has no program file?
  bool get isWindowsCore => pid == 0 || pid == 4;

}

/// All connections of one program, shown as one card.
class ProgramGroup {
  ProgramGroup._(this.key, this.rows, this.reasons, this.score);

  /// Builds a group. [rows] must all belong to the same program.
  factory ProgramGroup(String key, List<ConnectionRow> rows) {
    final sorted = [...rows]
      ..sort((a, b) => b.risk.score.compareTo(a.risk.score));
    final seen = <String>{};
    final reasons = <RiskReason>[
      for (final r in sorted)
        for (final reason in r.risk.reasons)
          if (seen.add(reason.title)) reason,
    ]..sort((a, b) => b.points.compareTo(a.points));
    // A program is as risky as its riskiest connection.
    final score = sorted.first.risk.score;
    return ProgramGroup._(key, sorted, reasons, score);
  }

  /// Stable id of the program (its file path, or its process id).
  final String key;

  /// Its connections, the most worrying first.
  final List<ConnectionRow> rows;

  /// Every warning clue found for this program, biggest first.
  final List<RiskReason> reasons;
  final int score;

  ConnectionRow get worst => rows.first;
  RiskLevel get level => RiskAssessment.levelForScore(score);
  String get fileName => worst.fileName;
  String? get path => worst.path;
  String? get folder => worst.folder;
  ProcessInfo? get process => worst.process;
  FileInfo? get file => worst.file;
  bool get isWindowsCore => worst.isWindowsCore;

  /// Good signs, without duplicates, from all of its connections.
  List<String> get goodSigns {
    final seen = <String>{};
    return [
      for (final r in rows)
        for (final g in r.risk.goodSigns)
          if (seen.add(g)) g,
    ];
  }

  /// Info lines, without duplicates.
  List<String> get notes {
    final seen = <String>{};
    return [
      for (final r in rows)
        for (final n in r.risk.notes)
          if (seen.add(n)) n,
    ];
  }

  Set<int> get pids => {for (final r in rows) r.pid};

  /// Who started it, as file names: parent first.
  List<String> get startedBy => [for (final a in worst.ancestors) a.fileName];

  /// Ways it starts by itself with Windows, without duplicates.
  List<AutostartEntry> get autostarts {
    final seen = <String>{};
    return [
      for (final r in rows)
        for (final e in r.autostarts)
          if (seen.add(e.key)) e,
    ];
  }

  /// Windows services this program runs, without duplicates.
  List<String> get services {
    final seen = <String>{};
    return [
      for (final r in rows)
        for (final s in r.process?.services ?? const <String>[])
          if (seen.add(s)) s,
    ];
  }

  /// Connections that go somewhere (not just waiting).
  List<ConnectionRow> get talking =>
      rows.where((r) => r.direction != Direction.listening).toList();

  /// "Open doors": the program waiting for others to connect.
  List<ConnectionRow> get listening =>
      rows.where((r) => r.direction == Direction.listening).toList();

  /// Shown with a "NEW" tag when the program only just started connecting.
  bool get isNew => rows.every((r) => r.isNew);
}

/// Folder part of a Windows (or POSIX) path, without the trailing slash.
String? folderOf(String? path) {
  if (path == null || path.isEmpty) return null;
  final i = path.lastIndexOf(RegExp(r'[\\/]'));
  if (i <= 0) return null;
  // Keep the slash for drive roots like "C:\".
  if (i == 2 && path[1] == ':') return path.substring(0, 3);
  return path.substring(0, i);
}

/// File name part of a Windows (or POSIX) path.
String fileNameOf(String path) {
  final i = path.lastIndexOf(RegExp(r'[\\/]'));
  return i < 0 ? path : path.substring(i + 1);
}
