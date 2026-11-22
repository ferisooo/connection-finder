// The app's brain: scans on a timer, checks files and IPs in the background,
// scores every connection and keeps the AI verdicts.

import 'dart:async';
import 'dart:io' show pid;
import 'dart:math' as math;

import 'package:flutter/foundation.dart';

import '../models.dart';
import '../services/ai_service.dart';
import '../services/geo_service.dart';
import '../services/ip_utils.dart';
import '../services/risk_engine.dart';
import '../services/scanner.dart';
import '../services/settings.dart';
import '../services/system_actions.dart';

enum RowFilter { all, suspicious, connected, listening }

class Stats {
  const Stats({
    required this.connections,
    required this.remoteIps,
    required this.programs,
    required this.suspicious,
    required this.dangerous,
  });

  final int connections;
  final int remoteIps;
  final int programs;
  final int suspicious;
  final int dangerous;
}

/// Works out which way a connection goes.
Direction directionOf(NetConnection c, Set<int> listeningPortsOfProcess) {
  if (c.isListening) return Direction.listening;
  if (c.remoteAddress.isEmpty) return Direction.other;
  if ((isLoopback(c.remoteAddress) && isLoopback(c.localAddress)) ||
      c.remoteAddress == c.localAddress) {
    return Direction.local;
  }
  if (c.pid == 0 || c.state == 'TimeWait' || c.state == 'Closed') {
    return Direction.other;
  }
  if (c.isTcp && listeningPortsOfProcess.contains(c.localPort)) {
    return Direction.incoming;
  }
  return Direction.outgoing;
}

const Map<Direction, int> _directionOrder = {
  Direction.incoming: 0,
  Direction.outgoing: 1,
  Direction.listening: 2,
  Direction.local: 3,
  Direction.other: 4,
};

int compareRows(ConnectionRow a, ConnectionRow b) {
  final byRisk = b.risk.score.compareTo(a.risk.score);
  if (byRisk != 0) return byRisk;
  final byDir =
      _directionOrder[a.direction]!.compareTo(_directionOrder[b.direction]!);
  if (byDir != 0) return byDir;
  final byName =
      a.fileName.toLowerCase().compareTo(b.fileName.toLowerCase());
  if (byName != 0) return byName;
  return a.connection.key.compareTo(b.connection.key);
}

class AppController extends ChangeNotifier {
  AppController({
    required this.settings,
    required this.scanner,
    required this.geo,
    required this.ai,
    this.actions = const SystemActions(),
    this.engine = const RiskEngine(),
  });

  final AppSettings settings;
  final ConnectionScanner scanner;
  final AiService ai;
  final SystemActions actions;
  final RiskEngine engine;
  final GeoLookup geo;

  static const int aiBatchSize = 8;
  static final DateTime _longAgo = DateTime.fromMillisecondsSinceEpoch(0);

  ScanResult? _last;
  List<ConnectionRow> _rows = const [];
  List<ConnectionRow>? _visibleCache;
  bool _scanning = false;
  bool _firstScanDone = false;
  DateTime? _lastUpdated;
  String? _error;

  final Map<String, FileInfo> _files = {};
  final Set<String> _inspecting = {};
  final Map<String, DateTime> _retryInspectAfter = {};
  final Map<String, DateTime> _firstSeen = {};

  final Map<String, AiVerdict> _verdicts = {};
  final Set<String> _aiBusy = {};
  bool _aiBatchRunning = false;
  int _aiBatchTotal = 0;
  int _aiBatchDone = 0;

  String _search = '';
  RowFilter _filter = RowFilter.all;

  Timer? _timer;
  bool? _timerAuto;
  int? _timerSeconds;
  bool _started = false;
  bool _disposed = false;

  // ---- read-only state for the UI --------------------------------------

  bool get scanning => _scanning;
  bool get firstScanDone => _firstScanDone;
  DateTime? get lastUpdated => _lastUpdated;
  String? get error => _error;
  bool get isAdmin => _last?.isAdmin ?? true;
  bool get demoMode => _last?.demo ?? false;
  bool get usingNetstatFallback => _last?.method == 'netstat';
  String get search => _search;
  RowFilter get filter => _filter;
  List<ConnectionRow> get allRows => _rows;
  bool get aiBatchRunning => _aiBatchRunning;
  int get aiBatchTotal => _aiBatchTotal;
  int get aiBatchDone => _aiBatchDone;

  AiVerdict? verdictFor(ConnectionRow row) => _verdicts[row.aiKey];
  bool isAsking(ConnectionRow row) => _aiBusy.contains(row.aiKey);
  bool isCheckingFile(ConnectionRow row) =>
      row.path != null && row.file == null &&
      _inspecting.contains(row.path!.toLowerCase());

  List<ConnectionRow> get visibleRows =>
      _visibleCache ??= _rows.where(_passesFilters).toList(growable: false);

  Stats get stats {
    final base = _rows.where(_passesLocalFilter).toList();
    return Stats(
      connections: base.length,
      remoteIps: base
          .map((r) => r.connection.remoteAddress)
          .where(isPublicIp)
          .toSet()
          .length,
      programs:
          base.map((r) => (r.path ?? r.fileName).toLowerCase()).toSet().length,
      suspicious:
          base.where((r) => r.risk.level == RiskLevel.suspicious).length,
      dangerous: base.where((r) => r.risk.level == RiskLevel.dangerous).length,
    );
  }

  /// Risky connections the AI hasn't judged yet (one per program+place).
  List<ConnectionRow> get pendingAiRows {
    final seen = <String>{};
    final out = <ConnectionRow>[];
    for (final r in _rows.where(_passesLocalFilter)) {
      if (r.risk.level == RiskLevel.safe) continue;
      final v = _verdicts[r.aiKey];
      if (v != null && !v.isError) continue;
      if (seen.add(r.aiKey)) out.add(r);
    }
    return out;
  }

  // ---- filters -----------------------------------------------------------

  set search(String value) {
    if (value == _search) return;
    _search = value;
    _visibleCache = null;
    notifyListeners();
  }

  set filter(RowFilter value) {
    if (value == _filter) return;
    _filter = value;
    _visibleCache = null;
    notifyListeners();
  }

  bool _passesLocalFilter(ConnectionRow r) {
    if (settings.showLocal) return true;
    if (r.direction == Direction.local || r.direction == Direction.other) {
      return false;
    }
    if (r.direction == Direction.listening &&
        isLoopback(r.connection.localAddress)) {
      return false;
    }
    return true;
  }

  bool _passesFilters(ConnectionRow r) {
    if (!_passesLocalFilter(r)) return false;
    switch (_filter) {
      case RowFilter.all:
        break;
      case RowFilter.suspicious:
        if (r.risk.level == RiskLevel.safe) return false;
      case RowFilter.connected:
        if (r.direction != Direction.outgoing &&
            r.direction != Direction.incoming) {
          return false;
        }
      case RowFilter.listening:
        if (r.direction != Direction.listening) return false;
    }
    final q = _search.trim().toLowerCase();
    if (q.isEmpty) return true;
    final c = r.connection;
    final haystack = <String?>[
      r.fileName,
      r.path,
      c.remoteAddress,
      '${c.remotePort}',
      '${c.localPort}',
      c.state,
      c.protocol,
      'pid ${r.pid}',
      r.geo?.country,
      r.geo?.countryCode,
      r.geo?.city,
      r.geo?.owner,
      r.file?.signer,
      r.file?.company,
      r.file?.product,
    ];
    return haystack.any((s) => s != null && s.toLowerCase().contains(q));
  }

  // ---- scanning ----------------------------------------------------------

  void start() {
    if (_started) return;
    _started = true;
    settings.addListener(_onSettingsChanged);
    _syncTimer();
    unawaited(refresh());
  }

  void _onSettingsChanged() {
    _syncTimer();
    _rebuild();
    if (settings.geoLookup) unawaited(_resolveGeo());
    notifyListeners();
  }

  void _syncTimer() {
    final auto = settings.autoRefresh;
    final secs = settings.refreshSeconds;
    if (_timerAuto == auto && _timerSeconds == secs) return;
    _timer?.cancel();
    _timer = null;
    _timerAuto = auto;
    _timerSeconds = secs;
    if (auto) {
      _timer = Timer.periodic(Duration(seconds: secs), (_) => refresh());
    }
  }

  Future<void> refresh() async {
    if (_scanning || _disposed) return;
    _scanning = true;
    notifyListeners();
    try {
      final result = await scanner.scan();
      if (_disposed) return;
      _last = result;
      _error = null;
      _lastUpdated = DateTime.now();
      _rebuild();
      _firstScanDone = true;
      unawaited(_inspectNewFiles());
      unawaited(_resolveGeo());
    } catch (e) {
      _error = e is ScanException ? e.message : 'Scan failed: $e';
    } finally {
      _scanning = false;
      if (!_disposed) notifyListeners();
    }
  }

  void _rebuild() {
    final result = _last;
    if (result == null) return;
    final now = DateTime.now();

    final listening = <int, Set<int>>{};
    for (final c in result.connections) {
      if (c.isTcp && c.state == 'Listen') {
        listening.putIfAbsent(c.pid, () => <int>{}).add(c.localPort);
      }
    }

    final rows = <ConnectionRow>[];
    final seen = <String>{};
    for (final c in result.connections) {
      final process = result.processes[c.pid];
      final path = process?.path;
      final file = path == null ? null : _files[path.toLowerCase()];
      final place = (c.remoteAddress.isEmpty || !settings.geoLookup)
          ? null
          : geo.cached(c.remoteAddress);
      final direction = directionOf(c, listening[c.pid] ?? const <int>{});
      final risk = engine.assess(RiskInput(
        connection: c,
        direction: direction,
        process: process,
        file: file,
        geo: place,
        flaggedCountries: settings.flaggedCountries,
        isAdmin: result.isAdmin,
        selfPid: pid,
        now: now,
      ));
      // Everything found by the very first scan was already there when the
      // app opened, so only later arrivals get the "NEW" tag.
      final first = _firstSeen.putIfAbsent(
          c.key, () => _firstScanDone ? now : _longAgo);
      seen.add(c.key);
      rows.add(ConnectionRow(
        connection: c,
        process: process,
        file: file,
        geo: place,
        risk: risk,
        direction: direction,
        firstSeen: first,
        isNew: now.difference(first) < const Duration(seconds: 60),
      ));
    }
    _firstSeen.removeWhere((key, _) => !seen.contains(key));
    rows.sort(compareRows);
    _rows = rows;
    _visibleCache = null;
  }

  Future<void> _inspectNewFiles() async {
    final result = _last;
    if (result == null) return;
    final now = DateTime.now();
    final todo = <String, String>{}; // lower-case key -> real path
    for (final c in result.connections) {
      final path = result.processes[c.pid]?.path;
      if (path == null) continue;
      final key = path.toLowerCase();
      if (_files.containsKey(key) || _inspecting.contains(key)) continue;
      final retry = _retryInspectAfter[key];
      if (retry != null && now.isBefore(retry)) continue;
      todo[key] = path;
    }
    if (todo.isEmpty) return;

    _inspecting.addAll(todo.keys);
    notifyListeners();
    try {
      final infos = await scanner.inspectFiles(todo.values.toList());
      for (final entry in todo.entries) {
        final info = infos[entry.value];
        if (info != null) {
          _files[entry.key] = info;
        } else {
          _retryInspectAfter[entry.key] =
              DateTime.now().add(const Duration(minutes: 2));
        }
      }
    } catch (_) {
      for (final key in todo.keys) {
        _retryInspectAfter[key] =
            DateTime.now().add(const Duration(minutes: 1));
      }
    } finally {
      _inspecting.removeAll(todo.keys);
    }
    if (_disposed) return;
    _rebuild();
    notifyListeners();
  }

  Future<void> _resolveGeo() async {
    if (!settings.geoLookup) return;
    final ips = _rows
        .map((r) => r.connection.remoteAddress)
        .where((ip) => ip.isNotEmpty)
        .toSet();
    final learned = await geo.resolve(ips);
    if (learned && !_disposed) {
      _rebuild();
      notifyListeners();
    }
  }

  // ---- AI helper ----------------------------------------------------------

  /// Asks the AI about one connection. Returns a message to show, or null.
  Future<String?> askAi(ConnectionRow row) async {
    if (!settings.aiReady) {
      return 'Add your AI key in Settings first (the gear button, top right).';
    }
    final key = row.aiKey;
    if (_aiBusy.contains(key)) return null;
    _aiBusy.add(key);
    notifyListeners();
    final config = settings.aiConfig;
    try {
      final res = await ai.analyze(config, [AiItem('c1', describeForAi(row))]);
      _verdicts[key] = res['c1'] ??
          AiVerdict.failed("The AI didn't answer about this connection.",
              provider: config.provider.shortName, model: config.model);
    } on AiException catch (e) {
      _verdicts[key] = AiVerdict.failed(e.message,
          provider: config.provider.shortName, model: config.model);
    } catch (e) {
      _verdicts[key] = AiVerdict.failed('Something went wrong: $e',
          provider: config.provider.shortName, model: config.model);
    } finally {
      _aiBusy.remove(key);
      if (!_disposed) notifyListeners();
    }
    return null;
  }

  /// Asks the AI about every risky connection it hasn't judged yet.
  Future<void> askAiAboutPending() async {
    if (_aiBatchRunning || !settings.aiReady) return;
    final rows = pendingAiRows;
    if (rows.isEmpty) return;

    _aiBatchRunning = true;
    _aiBatchTotal = rows.length;
    _aiBatchDone = 0;
    _aiBusy.addAll(rows.map((r) => r.aiKey));
    notifyListeners();

    final config = settings.aiConfig;
    AiVerdict fail(String msg) => AiVerdict.failed(msg,
        provider: config.provider.shortName, model: config.model);

    try {
      for (var i = 0; i < rows.length; i += aiBatchSize) {
        final chunk = rows.sublist(i, math.min(i + aiBatchSize, rows.length));
        final items = [
          for (var j = 0; j < chunk.length; j++)
            AiItem('c${j + 1}', describeForAi(chunk[j])),
        ];
        try {
          final res = await ai.analyze(config, items);
          for (var j = 0; j < chunk.length; j++) {
            _verdicts[chunk[j].aiKey] =
                res['c${j + 1}'] ?? fail('The AI skipped this one. Try again.');
          }
        } on AiException catch (e) {
          // Problems like a wrong key affect every request, so stop here.
          for (final r in rows.sublist(i)) {
            _verdicts[r.aiKey] = fail(e.message);
          }
          break;
        } catch (e) {
          for (final r in chunk) {
            _verdicts[r.aiKey] = fail('Something went wrong: $e');
          }
        }
        _aiBatchDone += chunk.length;
        _aiBusy.removeAll(chunk.map((r) => r.aiKey));
        if (_disposed) return;
        notifyListeners();
      }
    } finally {
      _aiBatchRunning = false;
      _aiBusy.removeAll(rows.map((r) => r.aiKey));
      if (!_disposed) notifyListeners();
    }
  }

  // ---- actions --------------------------------------------------------------

  Future<ActionResult> revealInExplorer(ConnectionRow row) {
    final path = row.path;
    if (path == null) {
      return Future.value(const ActionResult(false,
          'Windows is hiding this folder. Try "Restart as admin".'));
    }
    return actions.revealInExplorer(path);
  }

  Future<ActionResult> stopProgram(ConnectionRow row) async {
    final result = await actions.killProcess(row.pid);
    if (result.ok) {
      await Future<void>.delayed(const Duration(milliseconds: 400));
      unawaited(refresh());
    }
    return result;
  }

  Future<bool> relaunchAsAdmin() => actions.relaunchAsAdmin();

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    if (_started) settings.removeListener(_onSettingsChanged);
    super.dispose();
  }
}
